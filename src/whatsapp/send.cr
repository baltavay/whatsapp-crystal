require "base64"
require "digest/sha256"
require "./jid"
require "./binary/node"
require "./pairing"
require "./proto/messages"
require "./store/prekeys"
require "./store/session"
require "./transport/connection"

module WhatsApp
  # Sender-key operations (crypto/group port) the wire layer depends on.
  abstract class GroupCrypto
    abstract def distribution(group_jid : String) : Bytes
    abstract def encrypt(group_jid : String, plaintext : Bytes) : Bytes
  end

  # A prekey bundle exactly as the server returns it (whatsmeow prekeys.go
  # nodeToPreKeyBundle); the session port consumes this without knowing about
  # binary nodes.
  struct PreKeyBundle
    getter registration_id : UInt32
    getter device_id : UInt32
    getter prekey_id : UInt32?
    getter prekey_public : Bytes?
    getter signed_prekey_id : UInt32
    getter signed_prekey_public : Bytes
    getter signed_prekey_signature : Bytes
    getter identity_key : Bytes

    def initialize(@registration_id, @device_id, @prekey_id, @prekey_public, @signed_prekey_id, @signed_prekey_public, @signed_prekey_signature, @identity_key)
    end
  end

  # Pairwise session operations (crypto/signal port) the wire layer depends on.
  abstract class PairwiseCrypto
    abstract def session?(device_jid : String) : Bool
    abstract def encrypt(device_jid : String, bundle : PreKeyBundle?, plaintext : Bytes) : Tuple(String, Bytes)
  end

  # Group message sender: resolves the group roster, discovers participant
  # devices, establishes pairwise sessions, distributes the sender key and
  # finally emits the <message> node (whatsmeow send.go: prepareMessageNode +
  # sendGroup).
  class Sender
    SENDER_KEY_MESSAGE_VERSION = 2

    def initialize(
      @connection : Native::Connection,
      @device : DeviceState,
      @group_crypto : GroupCrypto,
      @pairwise : PairwiseCrypto,
    )
    end

    # libsignal pads plaintext with a count byte repeated (whatsmeow
    # message.go padMessage); receivers strip it, so an unpadded message is
    # silently truncated and only shows as "waiting for this message".
    def self.pad_message(plaintext : Bytes) : Bytes
      count = (Random::Secure.random_bytes(1)[0] & 0x0f).to_i
      count = 15 if count == 0
      padded = Bytes.new(plaintext.size + count)
      padded[0, plaintext.size].copy_from(plaintext)
      count.times { |index| padded[plaintext.size + index] = count.to_u8 }
      padded
    end

    def self.unpad_message(padded : Bytes) : Bytes
      raise ArgumentError.new("cannot unpad an empty message") if padded.empty?
      count = padded[padded.size - 1].to_i
      raise ArgumentError.new("invalid padding length #{count}") unless count >= 1 && count <= 16 && count <= padded.size
      padded[0, padded.size - count]
    end

    def send_group_message(group_jid : String, id : String, type : String, message : Proto::Message, media_type : String? = nil) : Nil
      roster = group_roster(group_jid)
      participants = roster[:participants]
      raise Native::Error.new(:not_in_group, "group #{group_jid} has no reachable participants") if participants.empty?

      targets = user_devices(participants).reject { |device| own_device?(device) }
      debug("participants: #{participants.join(", ")}")
      debug("target devices: #{targets.join(", ")}")
      raise Native::Error.new(:no_devices, "no recipient devices for #{group_jid}") if targets.empty?

      distribution = Proto::SenderKeyDistributionMessage.new
      distribution.group_id = group_jid
      distribution.axolotl_sender_key_distribution_message = @group_crypto.distribution(group_jid)
      distribution_plaintext = self.class.pad_message(Proto::Message.new.tap(&.sender_key_distribution = distribution).encode)

      bundles = fetch_bundles(targets)
      to_nodes = [] of Binary::Node
      distributed_new_session = false
      targets.each do |device|
        enc_type, ciphertext = @pairwise.encrypt(device, bundles[device]?, distribution_plaintext)
        distributed_new_session = true if enc_type == "pkmsg"
        to_nodes << Binary::Node.new("to", {"jid" => device}, nil, [
          Binary::Node.new("enc", {"v" => "2", "type" => enc_type}, ciphertext),
        ])
      end

      encrypted = @group_crypto.encrypt(group_jid, self.class.pad_message(message.encode))
      enc_attrs = {"v" => "2", "type" => "skmsg"}
      enc_attrs["mediatype"] = media_type.not_nil! if media_type

      attributes = {
        "id"    => id,
        "to"    => group_jid,
        "type"  => type,
        "phash" => participant_hash(targets),
      }
      # LID-addressed groups must say so, or the server accepts the node without
      # delivering it.
      if mode = roster[:addressing_mode]
        attributes["addressing_mode"] = mode
      end
      children = [Binary::Node.new("participants", nil, nil, to_nodes)]
      # Recipients that received a fresh prekey message need our ADV device
      # identity to verify us (whatsmeow send.go makeDeviceIdentityNode).
      if distributed_new_session
        children << Binary::Node.new("device-identity", nil, device_identity)
      end
      children << Binary::Node.new("enc", enc_attrs, encrypted)
      node = Binary::Node.new("message", attributes, nil, children)

      if ENV["WHATSAPP_DEBUG"]?
        debug("message node hex: #{Binary::Codec.encode(node).map { |byte| byte.to_s(16).rjust(2, '0') }.join}")
      end
      response = @connection.request(node)
      return unless response
      if response.tag == "error"
        code = response.attribute("code") || "unknown"
        text = response.attribute("text") || "send rejected"
        raise Native::Error.new(:send_failed, "server rejected the group message (#{code} #{text})")
      end
    end

    # The group's ADV device identity, serialized as recipients expect it.
    private def device_identity : Bytes
      account = @device.account || raise Native::Error.new(:pairing, "device has no ADV identity")
      account.encode
    end

    # Members of a group plus the group's addressing mode
    # (whatsmeow group.go getGroupInfo).
    def group_roster(group_jid : String) : NamedTuple(participants: Array(String), addressing_mode: String?)
      request = Binary::Node.new("iq", {
        "type"  => "get",
        "xmlns" => "w:g2",
        "to"    => group_jid,
        "id"    => request_id,
      }, nil, [Binary::Node.new("query", {"request" => "interactive"})])
      debug("group info request: #{describe(request)}")
      response = @connection.request(request) || raise Native::Error.new(:group_info_failed, "no response to the group info query")
      debug("group info response: #{describe(response)}")
      group = response.child("group") || raise Native::Error.new(:group_info_failed, "group info response has no <group>")
      participants = group.children.select { |child| child.tag == "participant" }.compact_map do |participant|
        participant.attribute("jid").presence
      end
      {participants: participants, addressing_mode: group.attribute("addressing_mode")}
    end

    # Device list per participant user, expanded into per-device JIDs
    # (whatsmeow user.go GetUserDevices + parseDeviceList).
    def user_devices(participants : Array(String)) : Array(String)
      raise ArgumentError.new("no participants to query") if participants.empty?
      list = Binary::Node.new("list", nil, nil, participants.map { |jid| Binary::Node.new("user", {"jid" => jid}) })
      request = Binary::Node.new("iq", {
        "type"  => "get",
        "xmlns" => "usync",
        "to"    => "s.whatsapp.net",
        "id"    => request_id,
      }, nil, [
        Binary::Node.new("usync", {
          "sid"     => request_id,
          "mode"    => "query",
          "last"    => "true",
          "index"   => "0",
          "context" => "message",
        }, nil, [
          Binary::Node.new("query", nil, nil, [Binary::Node.new("devices", {"version" => "2"})]),
          list,
        ]),
      ])
      debug("usync request: #{describe(request)}")
      response = @connection.request(request) || raise Native::Error.new(:usync_failed, "no response to the device list query")
      debug("usync response: #{describe(response)}")
      usync = response.child("usync") || response
      devices = [] of String
      (usync.child("list") || usync).children.each do |user|
        next unless user.tag == "user"
        user_jid = user.attribute("jid")
        next unless user_jid
        device_list = user.child("devices").try(&.child("device-list"))
        next unless device_list
        user_part, server_part = user_jid.split('@', 2)
        device_list.children.each do |device|
          next unless device.tag == "device"
          id = device.attribute("id")
          next unless id
          next if device.attribute("is_hosted") == "true"
          # Device 0 is the account's primary device and WhatsApp's canonical
          # form omits the device suffix entirely: "user@lid", never "user:0@lid".
          # A ":0" form is silently ignored by the server, which is what blocked
          # prekey bundle fetches.
          devices << (id == "0" ? "#{user_part}@#{server_part}" : "#{user_part}:#{id}@#{server_part}")
        end
      end
      devices.uniq
    end

    # Prekey bundles for the devices that have no session yet (whatsmeow
    # prekeys.go fetchPreKeys + nodeToPreKeyBundle).
    def fetch_bundles(device_jids : Array(String)) : Hash(String, PreKeyBundle)
      missing = device_jids.reject { |device| @pairwise.session?(device) }
      return Hash(String, PreKeyBundle).new if missing.empty?

      users = missing.map { |device| Binary::Node.new("user", {"jid" => device, "reason" => "identity"}) }
      request = Binary::Node.new("iq", {
        "type"  => "get",
        "xmlns" => "encrypt",
        "to"    => "s.whatsapp.net",
        "id"    => request_id,
      }, nil, [Binary::Node.new("key", nil, nil, users)])
      debug("bundle request: #{describe(request)}")
      response = @connection.request(request) || raise Native::Error.new(:prekey_fetch_failed, "no response to the prekey bundle query")
      if ENV["WHATSAPP_DEBUG"]? && response
        (response.child("list") || response).children.each do |user|
          next unless user.tag == "user"
          debug("raw bundle #{user.attribute("jid")}: #{user.children.map { |child| "#{child.tag}=#{child.content.try { |c| c[0, Math.min(8, c.size)].map { |b| b.to_s(16).rjust(2, '0') }.join } || ""}" }.join(" ")}")
        end
      end

      bundles = Hash(String, PreKeyBundle).new
      (response.child("list") || response).children.each do |user|
        next unless user.tag == "user"
        jid = user.attribute("jid") || next
        bundle = parse_bundle(user) || next
        if ENV["WHATSAPP_DEBUG"]?
          debug("parsed bundle #{jid}: reg=#{bundle.registration_id} device=#{bundle.device_id} " \
                "opk=#{bundle.prekey_id}/#{bundle.prekey_public.try(&.size)} " \
                "spk=#{bundle.signed_prekey_id}/#{bundle.signed_prekey_public.size} " \
                "sig=#{bundle.signed_prekey_signature.size} identity=#{bundle.identity_key.size}")
        end
        bundles[jid] = bundle
      end
      raise Native::Error.new(:prekey_fetch_failed, "no usable prekey bundles for #{missing.join(", ")}") if bundles.empty?
      bundles
    end

    private def parse_bundle(user : Binary::Node) : PreKeyBundle?
      keys = user.child("keys") || user
      registration = keys.child("registration") || return nil
      identity = keys.child("identity") || return nil
      signed_key = keys.child("skey") || return nil
      registration_id = decode_registration_id(registration.content) || return nil
      signed_id = decode_key_id(signed_key.child("id").try(&.content)) || return nil
      signed_value = signed_key.child("value").try(&.content) || return nil
      signature = signed_key.child("signature").try(&.content) || return nil
      identity_key = identity.content || return nil

      one_time = keys.child("key")
      prekey_id = one_time.try(&.child("id").try(&.content)).try { |value| decode_key_id(value) }
      prekey_public = one_time.try(&.child("value").try(&.content))

      PreKeyBundle.new(
        registration_id: registration_id,
        device_id: JID.parse_full(user.attribute("jid") || "").device,
        prekey_id: prekey_id,
        prekey_public: prekey_public,
        signed_prekey_id: signed_id,
        signed_prekey_public: signed_value,
        signed_prekey_signature: signature,
        identity_key: identity_key,
      )
    end

    private def decode_key_id(value : Bytes?) : UInt32?
      return nil unless value && value.size <= 4
      padded = Bytes.new(4)
      padded[4 - value.size, value.size].copy_from(value)
      IO::ByteFormat::BigEndian.decode(UInt32, padded)
    rescue
      nil
    end

    private def decode_registration_id(value : Bytes?) : UInt32?
      return nil unless value && value.size == 4
      IO::ByteFormat::BigEndian.decode(UInt32, value)
    rescue
      nil
    end

    # whatsmeow send.go participantListHashV2: "2:" plus the first six bytes of
    # the SHA-256 over the sorted device strings, base64 without padding.
    def participant_hash(device_jids : Array(String)) : String
      joined = device_jids.sort.join
      digest = Digest::SHA256.digest(joined.to_slice)
      # whatsmeow uses base64.RawStdEncoding (standard alphabet, no padding).
      "2:#{Base64.strict_encode(digest[0, 6]).rchop("==")}"
    end

    # Our own device appears in the device list under both the PN and the LID
    # form; neither should receive a pairwise copy (whatsmeow compares against
    # ownJID and ownLID).
    private def own_device?(device_jid : String) : Bool
      target = JID.parse_full(device_jid)
      [@device.jid, @device.lid].compact.any? do |own|
        own_jid = JID.parse_full(own)
        own_jid.user == target.user && own_jid.device == target.device
      end
    end

    private def describe(node : Binary::Node, depth : Int32 = 0) : String
      attributes = node.attrs.map { |key, value| "#{key}=#{value}" }.join(" ")
      text = String.build do |io|
        io << node.tag
        io << '[' << attributes << ']' unless attributes.empty?
        io << "(" << node.content.not_nil!.size << "B)" if node.content
      end
      return text if depth >= 2 || node.children.empty?
      "#{text}<#{node.children.map { |child| describe(child, depth + 1) }.join(" ")}>"
    end

    private def debug(message : String) : Nil
      STDERR.puts message if ENV["WHATSAPP_DEBUG"]?
    end

    private def request_id : String
      Base64.urlsafe_encode(Random::Secure.random_bytes(8), padding: false)
    end
  end
end

require "openssl/hmac"
require "base64"
require "json"
require "../../crypto/hkdf"
require "../../crypto/curve25519"

module WhatsApp
  module Crypto
    module Signal
      # record/SessionRecord.go:7-9 limits the previous-state list to 40.
      MAX_ARCHIVED_STATES = 40

      module Ratchet
        # Libsignal ratchet/KDF algorithms. The source paths cited on every
        # derivation are the v0.2.2 implementations this code mirrors.
        extend self

        # ratchet/Ratchet.go:18-23,77-84 derives 64 initial bytes from
        # 0xff*32 || the ordered X3DH DH outputs, HKDF-SHA256, nil salt,
        # info "WhisperText"; first 32 bytes are root, next 32 chain.
        def initial_keys(master_secret : Bytes) : Tuple(Bytes, Bytes)
          derived = WhatsApp::Crypto::HKDF.derive(master_secret, Bytes.new(0), "WhisperText".to_slice, 64)
          {derived[0, 32].dup, derived[32, 32].dup}
        end

        # keys/root/RootKey.go:40-58: HKDF-SHA256(ikm=DH, salt=root,
        # info="WhisperRatchet", length=64), split root || chain.
        def root_step(root_key : Bytes, dh_output : Bytes) : Tuple(Bytes, Bytes)
          validate_key!(root_key, "root key")
          validate_key!(dh_output, "DH output")
          derived = WhatsApp::Crypto::HKDF.derive(dh_output, root_key, "WhisperRatchet".to_slice, 64)
          {derived[0, 32].dup, derived[32, 32].dup}
        end

        # keys/chain/ChainKey.go:12-13,83-104: HMAC-SHA256(chain, 0x01)
        # derives the current message seed; HMAC-SHA256(chain, 0x02) advances.
        def chain_step(chain_key : Bytes) : Tuple(Bytes, Bytes)
          validate_key!(chain_key, "chain key")
          {hmac(chain_key, Bytes[1_u8]), hmac(chain_key, Bytes[2_u8])}
        end

        # keys/chain/ChainKey.go:89-128 and keys/message/MessageKey.go:5-18:
        # HKDF-SHA256(seed, empty salt, "WhisperMessageKeys", 80), laid out
        # cipher key 32 || MAC key 32 || IV 16.
        def message_keys(chain_key : Bytes) : Tuple(MessageKeys, Bytes)
          seed, next_chain = chain_step(chain_key)
          raw = WhatsApp::Crypto::HKDF.derive(seed, Bytes.new(0), "WhisperMessageKeys".to_slice, 80)
          {MessageKeys.new(raw[0, 32].dup, raw[32, 32].dup, raw[64, 16].dup), next_chain}
        end

        def hmac(key : Bytes, value : Bytes) : Bytes
          OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, key, value)
        end

        def x3dh_sender(our_identity : Curve25519KeyPair, our_base : Curve25519KeyPair,
                        their_identity : Bytes, their_signed_prekey : Bytes,
                        their_prekey : Bytes?) : Tuple(Bytes, Bytes)
          # ratchet/Ratchet.go:33-74 establishes this exact initiator order:
          # 0xff*32 || DH(IK_A,SPK_B) || DH(EK_A,IK_B) || DH(EK_A,SPK_B)
          # || optional DH(EK_A,OPK_B).
          master = Bytes.new(32, 0xff_u8)
          master += our_identity.shared_secret(their_signed_prekey)
          master += our_base.shared_secret(their_identity)
          master += our_base.shared_secret(their_signed_prekey)
          if key = their_prekey
            master += our_base.shared_secret(key)
          end
          initial_keys(master)
        end

        def x3dh_receiver(our_identity : Curve25519KeyPair, our_signed_prekey : Curve25519KeyPair,
                          our_prekey : Curve25519KeyPair?, their_identity : Bytes,
                          their_base : Bytes) : Tuple(Bytes, Bytes)
          # ratchet/Ratchet.go:98-141 establishes the receiver's mirrored order:
          # 0xff*32 || DH(IK_B,SPK_B) || DH(IK_A,EK_B) || DH(SPK_B,EK_B)
          # || optional DH(OPK_B,EK_B).
          master = Bytes.new(32, 0xff_u8)
          master += our_signed_prekey.shared_secret(their_identity)
          master += our_identity.shared_secret(their_base)
          master += our_signed_prekey.shared_secret(their_base)
          if key = our_prekey
            master += key.shared_secret(their_base)
          end
          initial_keys(master)
        end

        private def validate_key!(key : Bytes, name : String) : Nil
          raise ArgumentError.new("#{name} must be 32 bytes") unless key.size == 32
        end
      end

      class ChainKey
        property key : Bytes
        property index : UInt32

        def initialize(@key : Bytes, @index : UInt32 = 0_u32)
          raise ArgumentError.new("chain key must be 32 bytes") unless @key.size == 32
        end

        def advance! : MessageKeys
          keys, next_key = Ratchet.message_keys(@key)
          @key = next_key
          @index += 1_u32
          keys
        end

        def clone : ChainKey
          ChainKey.new(@key.dup, @index)
        end
      end

      class ReceiveChain
        getter public_key : Bytes
        property chain_key : ChainKey

        def initialize(public_key : Bytes, @chain_key : ChainKey)
          @public_key = public_key.dup
        end
      end

      # SessionState keeps one live session, its receive chains and skipped
      # keys; archived states are serialized independently for old-session reads.
      class SessionState
        property root_key : Bytes
        property sender_ratchet : Curve25519KeyPair?
        property sender_chain : ChainKey?
        property receiver_chains : Hash(String, ReceiveChain)
        property remote_ratchet_key : Bytes?
        property previous_counter : UInt32
        property local_identity : Bytes
        property remote_identity : Bytes
        property local_registration_id : UInt32
        property remote_registration_id : UInt32
        property base_key : Bytes?
        property prekey_id : UInt32?
        property signed_prekey_id : UInt32?
        property unacknowledged_prekey : Bool
        property skipped_keys : Hash(String, MessageKeys)
        property archived_states : Array(Bytes)

        def initialize(@root_key : Bytes, @local_identity : Bytes, @remote_identity : Bytes,
                       @local_registration_id : UInt32, @remote_registration_id : UInt32,
                       @sender_ratchet : Curve25519KeyPair? = nil, @sender_chain : ChainKey? = nil,
                       @previous_counter : UInt32 = 0_u32, @base_key : Bytes? = nil,
                       @prekey_id : UInt32? = nil, @signed_prekey_id : UInt32? = nil,
                       @unacknowledged_prekey : Bool = false)
          @receiver_chains = Hash(String, ReceiveChain).new
          @remote_ratchet_key = nil
          @skipped_keys = Hash(String, MessageKeys).new
          @archived_states = [] of Bytes
        end

        def add_receiver_chain(public_key : Bytes, chain : ChainKey) : Nil
          @receiver_chains[public_key_id(public_key)] = ReceiveChain.new(public_key, chain)
          @remote_ratchet_key = public_key.dup
        end

        def receiver_chain(public_key : Bytes) : ReceiveChain?
          @receiver_chains[public_key_id(public_key)]?
        end

        def self.skipped_id(public_key : Bytes, counter : UInt32) : String
          "#{Base64.strict_encode(public_key)}:#{counter}"
        end

        def add_skipped(public_key : Bytes, counter : UInt32, keys : MessageKeys) : Nil
          raise WhatsApp::Error.new("too many skipped Signal message keys") if @skipped_keys.size >= MAX_SKIPPED_KEYS
          @skipped_keys[self.class.skipped_id(public_key, counter)] = keys
        end

        def clone : SessionState
          self.class.from_bytes(to_bytes)
        end

        def to_bytes : Bytes
          encode(true)
        end

        def archival_bytes : Bytes
          encode(false)
        end

        def self.from_bytes(bytes : Bytes) : SessionState
          json = JSON.parse(String.new(bytes))
          hash = json.as_h
          sender = if value = hash["sender_ratchet"]?
                     pair = value.as_h
                     Curve25519KeyPair.new(decode(pair["private"].as_s), decode(pair["public"].as_s))
                   end
          sender_chain = if value = hash["sender_chain"]?
                           chain = value.as_h
                           ChainKey.new(decode(chain["key"].as_s), chain["index"].as_i64.to_u32)
                         end
          state = new(decode(hash["root_key"].as_s), decode(hash["local_identity"].as_s),
            decode(hash["remote_identity"].as_s), hash["local_registration_id"].as_i64.to_u32,
            hash["remote_registration_id"].as_i64.to_u32, sender, sender_chain,
            hash["previous_counter"].as_i64.to_u32,
            hash["base_key"].as_s.empty? ? nil : decode(hash["base_key"].as_s),
            nullable_uint(hash["prekey_id"]?), nullable_uint(hash["signed_prekey_id"]?),
            hash["unacknowledged_prekey"].as_bool)
          if remote = hash["remote_ratchet_key"].as_s
            state.remote_ratchet_key = decode(remote) unless remote.empty?
          end
          hash["receiver_chains"].as_a.each do |entry|
            item = entry.as_h
            pub = decode(item["public_key"].as_s)
            state.receiver_chains[public_key_id(pub)] = ReceiveChain.new(pub,
              ChainKey.new(decode(item["key"].as_s), item["index"].as_i64.to_u32))
          end
          hash["skipped_keys"].as_a.each do |entry|
            item = entry.as_h
            state.skipped_keys[item["id"].as_s] = MessageKeys.new(decode(item["cipher"].as_s),
              decode(item["mac"].as_s), decode(item["iv"].as_s))
          end
          if archived = hash["archived"]?
            archived.as_a.each { |entry| state.archived_states << decode(entry.as_s) }
          end
          state
        rescue ex : KeyError | TypeCastError | ArgumentError
          raise WhatsApp::Error.new("invalid serialized Signal session state: #{ex.message}")
        end

        private def encode(include_archived : Bool) : Bytes
          JSON.build do |json|
            json.object do
              json.field "root_key", Base64.strict_encode(@root_key)
              json.field "local_identity", Base64.strict_encode(@local_identity)
              json.field "remote_identity", Base64.strict_encode(@remote_identity)
              json.field "local_registration_id", @local_registration_id
              json.field "remote_registration_id", @remote_registration_id
              json.field "previous_counter", @previous_counter
              json.field "base_key", @base_key ? Base64.strict_encode(@base_key.not_nil!) : ""
              json.field "prekey_id", @prekey_id
              json.field "signed_prekey_id", @signed_prekey_id
              json.field "unacknowledged_prekey", @unacknowledged_prekey
              json.field "remote_ratchet_key", @remote_ratchet_key ? Base64.strict_encode(@remote_ratchet_key.not_nil!) : ""
              json.field "sender_ratchet" do
                if pair = @sender_ratchet
                  json.object do
                    json.field "private", Base64.strict_encode(pair.private_key)
                    json.field "public", Base64.strict_encode(pair.public_key)
                  end
                else
                  json.null
                end
              end
              json.field "sender_chain" do
                if chain = @sender_chain
                  json.object do
                    json.field "key", Base64.strict_encode(chain.key)
                    json.field "index", chain.index
                  end
                else
                  json.null
                end
              end
              json.field "receiver_chains" do
                json.array do
                  @receiver_chains.each_value do |chain|
                    json.object do
                      json.field "public_key", Base64.strict_encode(chain.public_key)
                      json.field "key", Base64.strict_encode(chain.chain_key.key)
                      json.field "index", chain.chain_key.index
                    end
                  end
                end
              end
              json.field "skipped_keys" do
                json.array do
                  @skipped_keys.each do |id, keys|
                    json.object do
                      json.field "id", id
                      json.field "cipher", Base64.strict_encode(keys.cipher_key)
                      json.field "mac", Base64.strict_encode(keys.mac_key)
                      json.field "iv", Base64.strict_encode(keys.iv)
                    end
                  end
                end
              end
              json.field "archived" do
                json.array do
                  @archived_states.each { |state| json.string(Base64.strict_encode(state)) } if include_archived
                end
              end
            end
          end.to_slice.dup
        end

        private def self.nullable_uint(value : JSON::Any?) : UInt32?
          return nil unless value && value.not_nil!.raw.is_a?(Int64)
          value.not_nil!.as_i64.to_u32
        end

        private def self.decode(value : String) : Bytes
          Base64.decode(value)
        end

        def self.public_key_id(public_key : Bytes) : String
          Base64.strict_encode(public_key)
        end

        private def public_key_id(public_key : Bytes) : String
          self.class.public_key_id(public_key)
        end
      end
    end
  end
end

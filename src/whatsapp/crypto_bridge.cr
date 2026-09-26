require "./crypto/group/group_cipher"
require "./crypto/group/sender_key"
require "./crypto/group/sender_key_distribution_message"
require "./crypto/signal/session"
require "./pairing"
require "./send"
require "./store/signal_store"

module WhatsApp
  # Bridges the wire layer's crypto seams to the libsignal ports. Keeping the
  # adapters here means Sender/Client never have to know the Signal object
  # graph, and the ports stay independently testable.
  class SignalPairwiseCrypto < PairwiseCrypto
    def initialize(@store : Crypto::Signal::Store::Base, @device : DeviceState)
      identity = @device.identity_key
      @store.local_registration_id = @device.registration_id unless @store.local_identity
      @builder = Crypto::Signal::SessionBuilder.new(@store, identity)
      @cipher = Crypto::Signal::SessionCipher.new(@store, identity)
    end

    def session?(device_jid : String) : Bool
      !@store.session(address(device_jid)).nil?
    end

    # Establishes a session from a freshly fetched bundle when one is supplied,
    # then returns the wire type ("pkmsg"/"msg") with the serialized ciphertext.
    def encrypt(device_jid : String, bundle : PreKeyBundle?, plaintext : Bytes) : Tuple(String, Bytes)
      target = address(device_jid)
      @builder.process_pre_key_bundle(to_signal_bundle(bundle), target) if bundle
      message = @cipher.encrypt(target, plaintext)
      {message.type == :prekey ? "pkmsg" : "msg", message.serialize}
    end

    # Decrypts an inbound pairwise message from the given sender. On first
    # contact the prekey message completes the peer's X3DH handshake against
    # the prekeys this device uploaded.
    def decrypt(device_jid : String, wire : Bytes) : Bytes
      @cipher.decrypt(address(device_jid), Crypto::Signal::CiphertextMessage.parse(wire))
    end

    private def to_signal_bundle(bundle : PreKeyBundle) : Crypto::Signal::PreKeyBundle
      Crypto::Signal::PreKeyBundle.new(
        registration_id: bundle.registration_id,
        device_id: bundle.device_id,
        prekey_id: bundle.prekey_id || 0_u32,
        # The session port ignores the one-time prekey when its id is 0 but
        # still requires a 32-byte buffer.
        prekey_public: bundle.prekey_public || Bytes.new(32),
        signed_prekey_id: bundle.signed_prekey_id,
        signed_prekey_public: bundle.signed_prekey_public,
        signed_prekey_signature: bundle.signed_prekey_signature,
        identity_key: bundle.identity_key,
      )
    end

    private def address(device_jid : String) : Crypto::Signal::Address
      parsed = JID.parse_full(device_jid)
      Crypto::Signal::Address.new(parsed.user, parsed.device)
    end
  end

  # Sender-key operations backed by the libsignal group cipher, persisted per
  # (group, own sender id) so the same chain survives restarts.
  class GroupSenderCrypto < GroupCrypto
    def initialize(@store : Store::Session, @device : DeviceState)
    end

    def distribution(group_jid : String) : Bytes
      record = sender_key(group_jid)
      message = Crypto::Group::SenderKeyDistributionMessage.new(
        record.id,
        record.iteration,
        record.chain_key,
        record.signing_public_key,
      )
      persist(group_jid, record)
      message.serialize
    end

    def encrypt(group_jid : String, plaintext : Bytes) : Bytes
      record = sender_key(group_jid)
      encrypted = Crypto::Group::GroupCipher.new.encrypt(record, plaintext)
      persist(group_jid, record)
      encrypted
    end

    private def sender_key(group_jid : String) : Crypto::Group::SenderKey
      if stored = @store.sender_key(group_jid, sender_id)
        return Crypto::Group::SenderKey.from_serialized(stored)
      end
      Crypto::Group::SenderKey.generate(sender_key_id)
    end

    private def persist(group_jid : String, record : Crypto::Group::SenderKey) : Nil
      @store.write_sender_key(group_jid, sender_id, record.serialize)
    end

    private def sender_id : String
      (@device.lid || @device.jid || "self").split('@', 2)[0]
    end

    private def sender_key_id : UInt32
      Random::Secure.random_bytes(4).reduce(0_u32) { |value, byte| (value << 8) | byte }
    end
  end
end

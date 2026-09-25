require "openssl/cipher"
require "openssl/hmac"
require "random/secure"
require "../xeddsa"
require "./protocol"
require "./ratchet"
require "../../store/signal_store"

module WhatsApp
  module Crypto
    module Signal
      private class OldCounterError < Exception
      end

      class SessionBuilder
        @store : Store::Base
        @our_identity_key_pair : Curve25519KeyPair
        @key_generator : Proc(Curve25519KeyPair)

        def initialize(@store : Store::Base, @our_identity_key_pair : Curve25519KeyPair,
                       @key_generator : Proc(Curve25519KeyPair) = ->Curve25519KeyPair.generate)
          @store.save_local_identity(@our_identity_key_pair)
        end

        def process_pre_key_bundle(bundle : PreKeyBundle, their_address : Address) : Nil
          trust_identity!(their_address, bundle.identity_key)
          # session/Session.go:202-207 verifies XEdDSA over the serialized
          # Curve25519 point (Djb type 0x05 followed by its 32-byte key).
          signed_prekey_input = Bytes.new(33)
          signed_prekey_input[0] = 5_u8
          signed_prekey_input[1, 32].copy_from(bundle.signed_prekey_public)
          unless WhatsApp::Crypto::XEdDSA.verify(bundle.identity_key, signed_prekey_input, bundle.signed_prekey_signature)
            raise WhatsApp::Error.new("invalid signed prekey signature")
          end

          base_key = @key_generator.call
          sender_ratchet = @key_generator.call
          optional_prekey = bundle.prekey_id == 0_u32 ? nil : bundle.prekey_public
          root, initial_chain = Ratchet.x3dh_sender(@our_identity_key_pair, base_key,
            bundle.identity_key, bundle.signed_prekey_public, optional_prekey)
          # session/Session.go:246-273 makes a fresh sending ratchet key,
          # derives its first chain from the signed prekey, and retains the
          # initial X3DH chain as the recipient's receive chain.
          next_root, sender_chain = Ratchet.root_step(root,
            sender_ratchet.shared_secret(bundle.signed_prekey_public))
          state = SessionState.new(next_root, @our_identity_key_pair.public_key,
            bundle.identity_key, @store.local_registration_id, bundle.registration_id,
            sender_ratchet, ChainKey.new(sender_chain), 0_u32, base_key.public_key,
            bundle.prekey_id == 0_u32 ? nil : bundle.prekey_id, bundle.signed_prekey_id, true)
          state.add_receiver_chain(bundle.signed_prekey_public, ChainKey.new(initial_chain))
          if previous_bytes = @store.session(their_address)
            previous = SessionState.from_bytes(previous_bytes)
            state.archived_states = previous.archived_states.dup
            state.archived_states << previous.archival_bytes
            while state.archived_states.size > MAX_ARCHIVED_STATES
              state.archived_states.shift
            end
          end
          @store.save_session(their_address, state.to_bytes)
          @store.save_identity(their_address, bundle.identity_key)
        end

        private def trust_identity!(address : Address, public_key : Bytes) : Nil
          if trusted = @store.identity(address)
            raise WhatsApp::Error.new("untrusted Signal identity for #{address.key}") unless trusted == public_key
          end
        end
      end

      class SessionCipher
        @store : Store::Base
        @our_identity_key_pair : Curve25519KeyPair
        @key_generator : Proc(Curve25519KeyPair)

        def initialize(@store : Store::Base, @our_identity_key_pair : Curve25519KeyPair,
                       @key_generator : Proc(Curve25519KeyPair) = ->Curve25519KeyPair.generate)
          @store.save_local_identity(@our_identity_key_pair)
        end

        def encrypt(their_address : Address, plaintext : Bytes) : CiphertextMessage
          encoded_state = @store.session(their_address) || raise WhatsApp::Error.new("no Signal session for #{their_address.key}")
          state = SessionState.from_bytes(encoded_state)
          chain = state.sender_chain || raise WhatsApp::Error.new("Signal sending chain is not initialized")
          ratchet = state.sender_ratchet || raise WhatsApp::Error.new("Signal sending ratchet is not initialized")
          message_counter = chain.index
          message_keys = chain.advance!
          body = encrypt_cbc(message_keys, plaintext)
          signal = Protocol.encode_signal(ratchet.public_key, message_counter,
            state.previous_counter, body, message_keys.mac_key,
            state.local_identity, state.remote_identity)
          result = if state.unacknowledged_prekey
                     base = state.base_key || raise WhatsApp::Error.new("missing Signal prekey base key")
                     signed_id = state.signed_prekey_id || raise WhatsApp::Error.new("missing signed prekey ID")
                     CiphertextMessage.new(:prekey, Protocol.encode_prekey(state.local_registration_id,
                       state.prekey_id, signed_id, base, state.local_identity, signal))
                   else
                     CiphertextMessage.new(:signal, signal)
                   end
          @store.save_session(their_address, state.to_bytes)
          result
        end

        def decrypt(their_address : Address, message : CiphertextMessage) : Bytes
          if message.type == :prekey
            decrypt_prekey(their_address, message.serialize)
          else
            decrypt_signal(their_address, Protocol.decode_signal(message.serialize))
          end
        end

        private def decrypt_prekey(address : Address, serialized : Bytes) : Bytes
          prekey = Protocol.decode_prekey(serialized)
          trust_identity!(address, prekey.identity_key)
          current : SessionState? = nil
          if encoded_state = @store.session(address)
            current = SessionState.from_bytes(encoded_state)
            known_base = current.not_nil!.base_key == prekey.base_key
            unless known_base
              known_base = current.not_nil!.archived_states.any? do |archived|
                SessionState.from_bytes(archived).base_key == prekey.base_key
              end
            end
            if known_base
              plaintext, state = decrypt_from_record(encoded_state, prekey.signal)
              state.unacknowledged_prekey = false
              @store.save_identity(address, prekey.identity_key)
              @store.save_session(address, state.to_bytes)
              return plaintext
            end
          end

          state = receive_prekey_state(address, prekey, current)
          plaintext = decrypt_signal_state!(state, prekey.signal)
          state.unacknowledged_prekey = false
          @store.save_identity(address, prekey.identity_key)
          @store.save_session(address, state.to_bytes)
          if prekey_id = prekey.prekey_id
            @store.remove_one_time_prekey(prekey_id)
          end
          plaintext
        end

        private def receive_prekey_state(address : Address, prekey : Protocol::PreKeyData,
                                         previous : SessionState?) : SessionState
          signed = @store.signed_prekey(prekey.signed_prekey_id) ||
                   raise WhatsApp::Error.new("missing signed prekey #{prekey.signed_prekey_id}")
          local_identity = @store.local_identity || @our_identity_key_pair
          one_time = if id = prekey.prekey_id
                       @store.one_time_prekey(id) || raise WhatsApp::Error.new("missing one-time prekey #{id}")
                     end
          root, chain = Ratchet.x3dh_receiver(local_identity, signed.key_pair, one_time,
            prekey.identity_key, prekey.base_key)
          # session/Session.go:133-175 seeds the responder with the signed
          # prekey as its initial sending ratchet and the X3DH chain at index 0.
          state = SessionState.new(root, local_identity.public_key, prekey.identity_key,
            @store.local_registration_id, prekey.registration_id, signed.key_pair,
            ChainKey.new(chain), 0_u32, prekey.base_key, prekey.prekey_id,
            prekey.signed_prekey_id, false)
          if previous
            state.archived_states = previous.archived_states.dup
            state.archived_states << previous.archival_bytes
            while state.archived_states.size > MAX_ARCHIVED_STATES
              state.archived_states.shift
            end
          end
          state
        end

        private def decrypt_signal(address : Address, message : Protocol::SignalData) : Bytes
          encoded_state = @store.session(address) || raise WhatsApp::Error.new("no Signal session for #{address.key}")
          state = SessionState.from_bytes(encoded_state)
          trust_identity!(address, state.remote_identity)
          plaintext, state = decrypt_from_record(encoded_state, message)
          @store.save_identity(address, state.remote_identity)
          @store.save_session(address, state.to_bytes)
          plaintext
        end

        # SessionCipher.go:250-286 tries current and previous states; the record
        # keeps the newest 40 previous states (record/SessionRecord.go:7-9).
        private def decrypt_from_record(encoded_state : Bytes, message : Protocol::SignalData) : Tuple(Bytes, SessionState)
          original = SessionState.from_bytes(encoded_state)
          current = SessionState.from_bytes(encoded_state)
          begin
            plaintext = decrypt_signal_state!(current, message)
            return {plaintext, current}
          rescue ex : OldCounterError
            raise WhatsApp::Error.new(ex.message || "replayed or expired Signal message counter")
          rescue current_error : WhatsApp::Error
            original.archived_states.size.times do |offset|
              index = original.archived_states.size - offset - 1
              archived = SessionState.from_bytes(original.archived_states[index])
              begin
                plaintext = decrypt_signal_state!(archived, message)
              rescue ex : OldCounterError
                raise WhatsApp::Error.new(ex.message || "replayed or expired Signal message counter")
              rescue WhatsApp::Error
                next
              end
              archives = original.archived_states.dup
              archives.delete_at(index)
              archives << original.archival_bytes
              while archives.size > MAX_ARCHIVED_STATES
                archives.shift
              end
              archived.archived_states = archives
              return {plaintext, archived}
            end
            raise current_error
          end
        end

        private def decrypt_signal_state!(state : SessionState, message : Protocol::SignalData) : Bytes
          raise WhatsApp::Error.new("unsupported Signal message version") unless VERSION == 3_u8
          message_id = SessionState.skipped_id(message.ratchet_key, message.counter)
          if skipped = state.skipped_keys[message_id]?
            plaintext = decrypt_with_keys(message, skipped, state.remote_identity, state.local_identity)
            state.skipped_keys.delete(message_id)
            state.unacknowledged_prekey = false
            return plaintext
          end

          chain = state.receiver_chain(message.ratchet_key)
          unless chain
            ratchet_to!(state, message.ratchet_key, message.previous_counter)
            chain = state.receiver_chain(message.ratchet_key)
          end
          receiver = chain || raise WhatsApp::Error.new("failed to establish Signal receiving chain")
          key_state = receiver.chain_key
          if message.counter < key_state.index
            raise OldCounterError.new("replayed or expired Signal message counter")
          end
          if message.counter - key_state.index > MAX_FUTURE_MESSAGES
            raise WhatsApp::Error.new("Signal message is too far in the future")
          end
          while key_state.index < message.counter
            skipped_counter = key_state.index
            state.add_skipped(message.ratchet_key, skipped_counter, key_state.advance!)
          end
          keys = key_state.advance!
          plaintext = decrypt_with_keys(message, keys, state.remote_identity, state.local_identity)
          state.unacknowledged_prekey = false
          plaintext
        end

        private def ratchet_to!(state : SessionState, remote_public : Bytes, previous_count : UInt32) : Nil
          # This libsignal revision computes old sender index - 1 as uint32;
          # zero therefore appears on the wire as 0xffffffff (SessionCipher.go:390).
          # Treat that wrapped sentinel as an empty previous chain, not a 2^32 skip.
          if old_remote = state.remote_ratchet_key
            if old_chain = state.receiver_chain(old_remote)
              skip_to!(state, old_remote, old_chain.chain_key, previous_count) unless previous_count == UInt32::MAX
            end
          end
          local_ratchet = state.sender_ratchet || raise WhatsApp::Error.new("Signal ratchet key is not initialized")
          receive_root, receive_chain = Ratchet.root_step(state.root_key, local_ratchet.shared_secret(remote_public))
          next_local = @key_generator.call
          send_root, send_chain = Ratchet.root_step(receive_root, next_local.shared_secret(remote_public))
          # session/SessionCipher.go:357-394 derives the receiver chain, rotates
          # the local ratchet key, derives the sender chain, and records PN.
          old_send_index = state.sender_chain.try(&.index) || 0_u32
          state.previous_counter = old_send_index &- 1_u32
          state.root_key = send_root
          state.sender_ratchet = next_local
          state.sender_chain = ChainKey.new(send_chain)
          state.add_receiver_chain(remote_public, ChainKey.new(receive_chain))
        end

        private def skip_to!(state : SessionState, public_key : Bytes, chain : ChainKey,
                             counter : UInt32) : Nil
          raise WhatsApp::Error.new("Signal previous-chain counter is too far in the future") if counter > chain.index && counter - chain.index > MAX_FUTURE_MESSAGES
          while chain.index < counter
            skipped_counter = chain.index
            state.add_skipped(public_key, skipped_counter, chain.advance!)
          end
        end

        private def decrypt_with_keys(message : Protocol::SignalData, keys : MessageKeys,
                                      sender_identity : Bytes, receiver_identity : Bytes) : Bytes
          Protocol.verify_mac!(message, keys.mac_key, sender_identity, receiver_identity)
          decrypt_cbc(keys, message.ciphertext)
        end

        private def encrypt_cbc(keys : MessageKeys, plaintext : Bytes) : Bytes
          cipher = OpenSSL::Cipher.new("aes-256-cbc")
          cipher.encrypt
          cipher.key = keys.cipher_key
          cipher.iv = keys.iv
          cipher.update(plaintext) + cipher.final
        end

        private def decrypt_cbc(keys : MessageKeys, ciphertext : Bytes) : Bytes
          raise WhatsApp::Error.new("invalid Signal AES-CBC ciphertext length") if ciphertext.empty? || ciphertext.size % 16 != 0
          cipher = OpenSSL::Cipher.new("aes-256-cbc")
          cipher.decrypt
          cipher.key = keys.cipher_key
          cipher.iv = keys.iv
          cipher.update(ciphertext) + cipher.final
        rescue ex : OpenSSL::Cipher::Error
          raise WhatsApp::Error.new("Signal AES-CBC decryption failed: #{ex.message}")
        end

        private def trust_identity!(address : Address, public_key : Bytes) : Nil
          if trusted = @store.identity(address)
            raise WhatsApp::Error.new("untrusted Signal identity for #{address.key}") unless trusted == public_key
          end
        end
      end
    end
  end
end

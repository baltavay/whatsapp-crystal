require "openssl/cipher"
require "openssl/hmac"
require "./../hkdf"
require "./../xeddsa"
require "./sender_key"
require "./sender_key_message"

module WhatsApp
  module Crypto
    module Group
      # Libsignal's GroupCipher uses HMAC(chain, 0x01/0x02) in
      # groups/ratchet/SenderChainKey.go, HKDF info "WhisperGroup" in
      # groups/ratchet/SenderMessageKey.go, AES-CBC in cipher/Cipher.go, and
      # verifies/signs SenderKeyMessage.Serialize() in groups/GroupCipher.go.
      class GroupCipher
        MAX_SKIP         = 2000_u32
        MESSAGE_KDF_INFO = "WhisperGroup"

        def encrypt(record : SenderKey, plaintext : Bytes) : Bytes
          self.class.sender_key_message(record, plaintext)
        end

        def decrypt(record : SenderKey, sender_key_message : Bytes) : Bytes
          message = SenderKeyMessage.deserialize(sender_key_message)
          raise WhatsApp::Error.new("sender-key iteration overflow") if message.iteration == UInt32::MAX
          raise WhatsApp::Error.new("sender-key id does not match record") unless message.id == record.id
          unless XEdDSA.verify(record.signing_public_key, message.unsigned_serialize, message.signature)
            raise WhatsApp::Error.new("sender-key signature verification failed")
          end

          if message.iteration < record.iteration
            seed = record.skipped_message_keys[message.iteration]?
            raise WhatsApp::Error.new("old or replayed sender-key message") unless seed
            plaintext = decrypt_with_seed(seed.not_nil!, message.ciphertext)
            record.take_message_key(message.iteration)
            return plaintext
          end

          gap = message.iteration - record.iteration
          raise WhatsApp::Error.new("sender-key iteration gap exceeds #{MAX_SKIP}") if gap > MAX_SKIP

          chain = record.chain_key
          skipped = [] of Tuple(UInt32, Bytes)
          counter = record.iteration
          selected_seed = Bytes.new(0)
          loop do
            seed = hmac(chain, Bytes[1_u8])
            next_chain = hmac(chain, Bytes[2_u8])
            if counter == message.iteration
              selected_seed = seed
              chain = next_chain
              break
            end
            skipped << {counter, seed}
            chain = next_chain
            counter += 1_u32
          end

          plaintext = decrypt_with_seed(selected_seed, message.ciphertext)
          skipped.each { |entry| record.remember_message_key(entry[0], entry[1]) }
          record.replace_chain!(message.iteration + 1_u32, chain)
          plaintext
        end

        def self.sender_key_message(record : SenderKey, plaintext : Bytes) : Bytes
          raise ArgumentError.new("sender-key plaintext must not be empty") if plaintext.empty?
          private_key = record.signing_private_key || raise WhatsApp::Error.new("sender signing private key is unavailable")
          seed = hmac(record.chain_key, Bytes[1_u8])
          next_chain = hmac(record.chain_key, Bytes[2_u8])
          iv, cipher_key = message_key(seed)
          ciphertext = encrypt_cbc(iv, cipher_key, plaintext)
          unsigned_body = SenderKeyMessage.unsigned_body(record.id, record.iteration, ciphertext)
          signature = XEdDSA.sign(private_key, unsigned_body)
          signed = SenderKeyMessage.new(record.id, record.iteration, ciphertext, signature).serialize
          raise WhatsApp::Error.new("sender-key iteration overflow") if record.iteration == UInt32::MAX
          record.replace_chain!(record.iteration + 1_u32, next_chain)
          signed
        end

        private def self.message_key(seed : Bytes) : Tuple(Bytes, Bytes)
          derived = HKDF.derive(seed, Bytes.new(0), MESSAGE_KDF_INFO.to_slice, 48)
          {derived[0, 16], derived[16, 32]}
        end

        private def self.encrypt_cbc(iv : Bytes, key : Bytes, plaintext : Bytes) : Bytes
          cipher = OpenSSL::Cipher.new("aes-256-cbc")
          cipher.encrypt
          cipher.key = key
          cipher.iv = iv
          cipher.update(plaintext) + cipher.final
        end

        private def decrypt_with_seed(seed : Bytes, ciphertext : Bytes) : Bytes
          derived = HKDF.derive(seed, Bytes.new(0), MESSAGE_KDF_INFO.to_slice, 48)
          iv = derived[0, 16]
          cipher_key = derived[16, 32]
          cipher = OpenSSL::Cipher.new("aes-256-cbc")
          cipher.decrypt
          cipher.key = cipher_key
          cipher.iv = iv
          cipher.update(ciphertext) + cipher.final
        end

        private def self.hmac(key : Bytes, data : Bytes) : Bytes
          OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, key, data)
        end

        private def hmac(key : Bytes, data : Bytes) : Bytes
          OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, key, data)
        end
      end
    end
  end
end

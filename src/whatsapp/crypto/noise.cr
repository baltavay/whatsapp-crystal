require "digest/sha256"
require "./aead"
require "./curve25519"
require "./hkdf"

module WhatsApp
  module Crypto
    class NoiseHandshake
      getter hash : Bytes
      getter salt : Bytes

      def initialize
        @hash = Bytes.new(0)
        @salt = Bytes.new(0)
        @key = Bytes.new(32)
        @counter = 0_u32
      end

      def start(pattern : String, header : Bytes) : self
        data = pattern.to_slice
        # WhatsApp uses the Noise pattern itself as the initial hash material
        # when it is exactly 32 bytes long (which the WA pattern is), instead
        # of hashing it. Hashing it here breaks the very first AEAD open.
        @hash = data.size == 32 ? data.dup : Digest::SHA256.digest(data)
        @salt = @hash.dup
        @key = @hash.dup
        @counter = 0_u32
        authenticate(header)
        self
      end

      def authenticate(data : Bytes) : Nil
        digest_input = Bytes.new(@hash.size + data.size)
        digest_input[0, @hash.size].copy_from(@hash)
        digest_input[@hash.size, data.size].copy_from(data)
        @hash = Digest::SHA256.digest(digest_input)
      end

      def encrypt(plaintext : Bytes) : Bytes
        ciphertext = AESGCM.encrypt(@key, nonce(@counter), plaintext, @hash)
        @counter += 1
        authenticate(ciphertext)
        ciphertext
      end

      def decrypt(ciphertext : Bytes) : Bytes
        plaintext = AESGCM.decrypt(@key, nonce(@counter), ciphertext, @hash)
        @counter += 1
        authenticate(ciphertext)
        plaintext
      end

      def mix_shared_secret(key_pair : Curve25519KeyPair, peer_public_key : Bytes) : self
        mix_into_key(key_pair.shared_secret(peer_public_key))
        self
      end

      def mix_into_key(shared_secret : Bytes) : self
        @counter = 0_u32
        expanded = HKDF.derive(shared_secret, @salt, Bytes.new(0), 64)
        @salt = expanded[0, 32]
        @key = expanded[32, 32]
        self
      end

      def transport_keys : Tuple(Bytes, Bytes)
        expanded = HKDF.derive(Bytes.new(0), @salt, Bytes.new(0), 64)
        {expanded[0, 32], expanded[32, 32]}
      end

      private def nonce(counter : UInt32) : Bytes
        value = Bytes.new(12)
        value[8] = (counter >> 24).to_u8
        value[9] = (counter >> 16).to_u8
        value[10] = (counter >> 8).to_u8
        value[11] = counter.to_u8
        value
      end
    end
  end
end

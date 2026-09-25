require "digest/sha256"
require "openssl/cipher"
require "random/secure"
require "./hkdf"

module WhatsApp
  module Crypto
    struct EncryptedMedia
      getter media_key : Bytes
      getter ciphertext : Bytes
      getter file_sha256 : Bytes
      getter file_enc_sha256 : Bytes
      getter plaintext_length : UInt64

      def initialize(@media_key, @ciphertext, @file_sha256, @file_enc_sha256, @plaintext_length : UInt64 = 0_u64)
      end
    end

    # WhatsApp media encryption: derive CBC/HMAC keys, encrypt with PKCS#7,
    # append the first 10 bytes of HMAC-SHA256(iv || ciphertext).
    def self.encrypt_media(plaintext : Bytes, media_info : String) : EncryptedMedia
      media_key = Random::Secure.random_bytes(32)
      media_keys = HKDF.derive(media_key, Bytes.new(32), media_info.to_slice, 112)
      iv = media_keys[0, 16]
      cipher_key = media_keys[16, 32]
      mac_key = media_keys[48, 32]

      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.encrypt
      cipher.key = cipher_key
      cipher.iv = iv
      ciphertext = cipher.update(plaintext) + cipher.final

      authenticated = iv + ciphertext
      mac = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, mac_key, authenticated)
      encrypted = ciphertext + mac[0, 10]
      file_sha256 = Digest::SHA256.digest(plaintext)
      file_enc_sha256 = Digest::SHA256.digest(encrypted)
      EncryptedMedia.new(media_key, encrypted, file_sha256, file_enc_sha256, plaintext.size.to_u64)
    end
  end
end

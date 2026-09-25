@[Link("crypto")]
lib LibCryptoGCM
  fun evp_cipher_ctx_new = EVP_CIPHER_CTX_new : Void*
  fun evp_cipher_ctx_free = EVP_CIPHER_CTX_free(ctx : Void*) : Void
  fun evp_aes_256_gcm = EVP_aes_256_gcm : Void*
  fun evp_encrypt_init_ex = EVP_EncryptInit_ex(ctx : Void*, cipher : Void*, engine : Void*, key : UInt8*, iv : UInt8*) : Int32
  fun evp_decrypt_init_ex = EVP_DecryptInit_ex(ctx : Void*, cipher : Void*, engine : Void*, key : UInt8*, iv : UInt8*) : Int32
  fun evp_encrypt_update = EVP_EncryptUpdate(ctx : Void*, out : UInt8*, out_len : Int32*, input : UInt8*, input_len : Int32) : Int32
  fun evp_decrypt_update = EVP_DecryptUpdate(ctx : Void*, out : UInt8*, out_len : Int32*, input : UInt8*, input_len : Int32) : Int32
  fun evp_encrypt_final_ex = EVP_EncryptFinal_ex(ctx : Void*, out : UInt8*, out_len : Int32*) : Int32
  fun evp_decrypt_final_ex = EVP_DecryptFinal_ex(ctx : Void*, out : UInt8*, out_len : Int32*) : Int32
  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : Void*, command : Int32, argument : Int32, data : UInt8*) : Int32
end

module WhatsApp
  module Crypto
    module AESGCM
      extend self

      KEY_SIZE             =   32
      NONCE_SIZE           =   12
      TAG_SIZE             =   16
      EVP_CTRL_GCM_GET_TAG = 0x10
      EVP_CTRL_GCM_SET_TAG = 0x11

      def available? : Bool
        true
      end

      def encrypt(key : Bytes, nonce : Bytes, plaintext : Bytes, associated_data : Bytes = Bytes.new(0)) : Bytes
        validate(key, nonce)
        ctx = LibCryptoGCM.evp_cipher_ctx_new
        raise Error.new("OpenSSL could not allocate AES-GCM context") if ctx.null?
        begin
          raise Error.new("OpenSSL AES-GCM initialization failed") unless LibCryptoGCM.evp_encrypt_init_ex(ctx, LibCryptoGCM.evp_aes_256_gcm, Pointer(Void).null, key, nonce) == 1
          output = Bytes.new(plaintext.size + TAG_SIZE + 16)
          written = 0
          if associated_data.size > 0
            raise Error.new("OpenSSL AES-GCM AAD failed") unless LibCryptoGCM.evp_encrypt_update(ctx, Pointer(UInt8).null, pointerof(written), associated_data, associated_data.size) == 1
          end
          raise Error.new("OpenSSL AES-GCM encryption failed") unless LibCryptoGCM.evp_encrypt_update(ctx, output, pointerof(written), plaintext, plaintext.size) == 1
          total = written
          final_written = 0
          raise Error.new("OpenSSL AES-GCM finalization failed") unless LibCryptoGCM.evp_encrypt_final_ex(ctx, output + total, pointerof(final_written)) == 1
          total += final_written
          tag = Bytes.new(TAG_SIZE)
          raise Error.new("OpenSSL AES-GCM tag generation failed") unless LibCryptoGCM.evp_cipher_ctx_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) == 1
          output[0, total] + tag
        ensure
          LibCryptoGCM.evp_cipher_ctx_free(ctx)
        end
      end

      def decrypt(key : Bytes, nonce : Bytes, ciphertext : Bytes, associated_data : Bytes = Bytes.new(0)) : Bytes
        validate(key, nonce)
        raise ArgumentError.new("AES-GCM ciphertext is shorter than its authentication tag") if ciphertext.size < TAG_SIZE
        payload = ciphertext[0, ciphertext.size - TAG_SIZE]
        tag = ciphertext[ciphertext.size - TAG_SIZE, TAG_SIZE]
        ctx = LibCryptoGCM.evp_cipher_ctx_new
        raise Error.new("OpenSSL could not allocate AES-GCM context") if ctx.null?
        begin
          raise Error.new("OpenSSL AES-GCM initialization failed") unless LibCryptoGCM.evp_decrypt_init_ex(ctx, LibCryptoGCM.evp_aes_256_gcm, Pointer(Void).null, key, nonce) == 1
          output = Bytes.new(payload.size + 16)
          written = 0
          if associated_data.size > 0
            raise Error.new("OpenSSL AES-GCM AAD failed") unless LibCryptoGCM.evp_decrypt_update(ctx, Pointer(UInt8).null, pointerof(written), associated_data, associated_data.size) == 1
          end
          raise Error.new("OpenSSL AES-GCM decryption failed") unless LibCryptoGCM.evp_decrypt_update(ctx, output, pointerof(written), payload, payload.size) == 1
          total = written
          raise Error.new("OpenSSL AES-GCM tag setup failed") unless LibCryptoGCM.evp_cipher_ctx_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) == 1
          final_written = 0
          raise Error.new("OpenSSL AES-GCM authentication failed") unless LibCryptoGCM.evp_decrypt_final_ex(ctx, output + total, pointerof(final_written)) == 1
          output[0, total + final_written]
        ensure
          LibCryptoGCM.evp_cipher_ctx_free(ctx)
        end
      end

      private def validate(key : Bytes, nonce : Bytes) : Nil
        raise ArgumentError.new("AES-256-GCM key must be 32 bytes") unless key.size == KEY_SIZE
        raise ArgumentError.new("AES-256-GCM nonce must be 12 bytes") unless nonce.size == NONCE_SIZE
      end
    end
  end
end

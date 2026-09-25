require "openssl/hmac"

module WhatsApp
  module Crypto
    # RFC 5869 HKDF-SHA256 used by WhatsApp media and Noise derivations.
    module HKDF
      extend self

      def extract(salt : Bytes, input_key_material : Bytes) : Bytes
        salt = Bytes.new(32) if salt.empty?
        OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, salt, input_key_material)
      end

      def expand(pseudorandom_key : Bytes, info : Bytes, length : Int32) : Bytes
        raise ArgumentError.new("HKDF output length must be between 0 and 8160 bytes") unless length >= 0 && length <= 255 * 32
        output = Bytes.new(length)
        previous = Bytes.new(0)
        offset = 0
        counter = 1_u8

        while offset < length
          block_input = Bytes.new(previous.size + info.size + 1)
          block_input[0, previous.size].copy_from(previous)
          block_input[previous.size, info.size].copy_from(info)
          block_input[block_input.size - 1] = counter
          previous = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, pseudorandom_key, block_input)
          copied = Math.min(previous.size, length - offset)
          output[offset, copied].copy_from(previous[0, copied])
          offset += copied
          counter += 1
        end
        output
      end

      def derive(input_key_material : Bytes, salt : Bytes, info : Bytes, length : Int32) : Bytes
        expand(extract(salt, input_key_material), info, length)
      end
    end
  end
end

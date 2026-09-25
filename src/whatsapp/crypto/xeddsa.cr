require "big"
require "digest/sha512"
require "random/secure"
require "./curve25519"

module WhatsApp
  module Crypto
    # Signal's XEdDSA: Ed25519 signatures made with Curve25519 keys. WhatsApp
    # uses it for the Noise certificate chain, the signed prekey and the ADV
    # device identity, so an Ed25519-only implementation cannot be verified or
    # produced correctly.
    #
    # Ported from libsignal's SignCurve25519.go (package ecc):
    #   * the Curve25519 private key doubled as a clamped Ed25519 scalar,
    #   * the nonce hashed with a 0xFE||0xFF..31 diversifier plus 64 random bytes,
    #   * the public key sign bit moved into the top bit of S.
    module XEdDSA
      extend self

      FIELD_PRIME    = (1.to_big_i << 255) - 19
      SCALAR_SIZE    = 32
      SIGNATURE_SIZE = 64

      NONCE_DIVERSIFIER = Bytes[
        0xfe_u8,
        0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8,
        0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8,
        0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8,
        0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8,
      ]

      def verify(curve25519_public_key : Bytes, message : Bytes, signature : Bytes) : Bool
        return false unless curve25519_public_key.size == 32 && signature.size == SIGNATURE_SIZE
        edwards = montgomery_to_edwards(curve25519_public_key)
        edwards[31] = (edwards[31] & 0x7f) | (signature[63] & 0x80)
        adjusted = signature.dup
        adjusted[63] &= 0x7f
        Ed25519KeyPair.verify(edwards, message, adjusted)
      rescue Error
        false
      end

      # Signs with a Curve25519 private key. The 64-byte random nonce is a
      # parameter so tests can make signatures reproducible.
      def sign(private_key : Bytes, message : Bytes, random : Bytes? = nil) : Bytes
        raise ArgumentError.new("X25519 private key must be 32 bytes") unless private_key.size == 32
        nonce_random = random || Random::Secure.random_bytes(64)
        raise ArgumentError.new("XEdDSA nonce must be 64 bytes") unless nonce_random.size == 64
        Crypto.ensure_sodium

        scalar = reduce_scalar(clamped(private_key))
        public_key = scalar_base_mult(scalar)

        digest = Digest::SHA512.new
        digest.update(NONCE_DIVERSIFIER)
        digest.update(private_key)
        digest.update(message)
        digest.update(nonce_random)
        nonce = reduce_scalar(digest.final)

        encoded_r = scalar_base_mult(nonce)

        digest = Digest::SHA512.new
        digest.update(encoded_r)
        digest.update(public_key)
        digest.update(message)
        challenge = reduce_scalar(digest.final)

        product = Bytes.new(SCALAR_SIZE)
        LibSodium.crypto_core_ed25519_scalar_mul(product, challenge, scalar)
        signature = Bytes.new(SIGNATURE_SIZE)
        signature[0, SCALAR_SIZE].copy_from(encoded_r)
        LibSodium.crypto_core_ed25519_scalar_add(signature[SCALAR_SIZE, SCALAR_SIZE], product, nonce)
        signature[63] = signature[63] | (public_key[31] & 0x80)
        signature
      end

      # ed_y = (mont_x - 1) / (mont_x + 1) mod 2**255 - 19, little-endian.
      def montgomery_to_edwards(public_key : Bytes) : Bytes
        raise ArgumentError.new("X25519 public key must be 32 bytes") unless public_key.size == 32
        u = little_endian_integer(public_key)
        numerator = (u - 1) % FIELD_PRIME
        denominator = (u + 1) % FIELD_PRIME
        y = denominator == 0 ? 0.to_big_i : (numerator * inverse(denominator)) % FIELD_PRIME
        encode_little_endian(y)
      end

      private def clamped(private_key : Bytes) : Bytes
        scalar = private_key.dup
        scalar[0] = scalar[0] & 248_u8
        scalar[31] = (scalar[31] & 127_u8) | 64_u8
        scalar
      end

      private def reduce_scalar(wide : Bytes) : Bytes
        padded = Bytes.new(64)
        padded[0, Math.min(wide.size, 64)].copy_from(wide[0, Math.min(wide.size, 64)])
        scalar = Bytes.new(SCALAR_SIZE)
        LibSodium.crypto_core_ed25519_scalar_reduce(scalar, padded)
        scalar
      end

      private def scalar_base_mult(scalar : Bytes) : Bytes
        point = Bytes.new(32)
        raise Error.new("XEdDSA base point multiplication failed") unless LibSodium.crypto_scalarmult_ed25519_base_noclamp(point, scalar) == 0
        point
      end

      private def inverse(value : BigInt) : BigInt
        # Extended Euclid; the modulus is prime so a plain inverse exists.
        old_r, r = FIELD_PRIME, value
        old_t, t = 0.to_big_i, 1.to_big_i
        while r != 0
          quotient = old_r // r
          old_r, r = r, old_r - quotient * r
          old_t, t = t, old_t - quotient * t
        end
        raise Error.new("X25519 coordinate is not invertible") unless old_r == 1
        old_t %= FIELD_PRIME
        old_t += FIELD_PRIME if old_t < 0
        old_t
      end

      private def little_endian_integer(bytes : Bytes) : BigInt
        value = 0.to_big_i
        (bytes.size - 1).downto(0) { |index| value = (value << 8) | bytes[index] }
        value
      end

      private def encode_little_endian(value : BigInt) : Bytes
        bytes = Bytes.new(32)
        remaining = value
        32.times do |index|
          bytes[index] = (remaining & 0xff).to_u8
          remaining >>= 8
        end
        bytes
      end
    end
  end
end

require "random/secure"

module WhatsApp
  module Crypto
    @[Link("sodium")]
    lib LibSodium
      fun sodium_init : Int32
      fun crypto_scalarmult_curve25519_base(q : UInt8*, n : UInt8*) : Int32
      fun crypto_scalarmult_curve25519(q : UInt8*, n : UInt8*, p : UInt8*) : Int32
      fun crypto_sign_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : Int32
      fun crypto_sign_detached(sig : UInt8*, siglen : UInt64*, message : UInt8*, message_len : UInt64, sk : UInt8*) : Int32
      fun crypto_sign_verify_detached(sig : UInt8*, message : UInt8*, message_len : UInt64, pk : UInt8*) : Int32
      # These three return void in libsodium, unlike the scalarmult status codes.
      fun crypto_core_ed25519_scalar_reduce(r : UInt8*, s : UInt8*) : Void
      fun crypto_core_ed25519_scalar_mul(r : UInt8*, x : UInt8*, y : UInt8*) : Void
      fun crypto_core_ed25519_scalar_add(z : UInt8*, x : UInt8*, y : UInt8*) : Void
      fun crypto_scalarmult_ed25519_base_noclamp(q : UInt8*, n : UInt8*) : Int32
    end

    struct Curve25519KeyPair
      getter private_key : Bytes
      getter public_key : Bytes

      def initialize(@private_key : Bytes, @public_key : Bytes)
      end

      def self.generate : self
        Crypto.ensure_sodium
        private_key = Random::Secure.random_bytes(32)
        public_key = Bytes.new(32)
        result = LibSodium.crypto_scalarmult_curve25519_base(public_key, private_key)
        raise Error.new("X25519 public key generation failed") unless result == 0
        new(private_key, public_key)
      end

      def shared_secret(peer_public_key : Bytes) : Bytes
        raise ArgumentError.new("X25519 public key must be 32 bytes") unless peer_public_key.size == 32
        shared = Bytes.new(32)
        result = LibSodium.crypto_scalarmult_curve25519(shared, @private_key, peer_public_key)
        raise Error.new("X25519 shared secret generation failed") unless result == 0
        shared
      end
    end

    struct Ed25519KeyPair
      getter seed : Bytes
      getter public_key : Bytes
      getter secret_key : Bytes

      def initialize(@seed : Bytes, @public_key : Bytes, @secret_key : Bytes)
      end

      def self.generate : self
        Crypto.ensure_sodium
        seed = Random::Secure.random_bytes(32)
        public_key = Bytes.new(32)
        secret_key = Bytes.new(64)
        result = LibSodium.crypto_sign_seed_keypair(public_key, secret_key, seed)
        raise Error.new("Ed25519 key generation failed") unless result == 0
        new(seed, public_key, secret_key)
      end

      def sign(message : Bytes) : Bytes
        signature = Bytes.new(64)
        signature_length = 0_u64
        result = LibSodium.crypto_sign_detached(signature, pointerof(signature_length), message, message.size.to_u64, @secret_key)
        raise Error.new("Ed25519 signing failed") unless result == 0
        signature[0, signature_length.to_i]
      end

      def self.verify(public_key : Bytes, message : Bytes, signature : Bytes) : Bool
        return false unless public_key.size == 32 && signature.size == 64
        LibSodium.crypto_sign_verify_detached(signature, message, message.size.to_u64, public_key) == 0
      end
    end

    def self.ensure_sodium : Nil
      raise Error.new("libsodium initialization failed") if LibSodium.sodium_init < 0
    end
  end
end

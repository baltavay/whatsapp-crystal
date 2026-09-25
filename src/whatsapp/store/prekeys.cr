require "base64"
require "json"
require "../crypto/curve25519"
require "../crypto/xeddsa"

module WhatsApp
  # Curve25519 prekeys as WhatsApp's Signal layer uses them: a one-time prekey
  # is a bare key pair, a signed prekey also carries the identity key's XEdDSA
  # signature over [0x05] || public key.
  struct PreKey
    DJB_TYPE = 5_u8

    getter id : UInt32
    getter key_pair : Crypto::Curve25519KeyPair
    getter signature : Bytes?

    def initialize(@id : UInt32, @key_pair : Crypto::Curve25519KeyPair, @signature : Bytes? = nil)
    end

    def public_key : Bytes
      @key_pair.public_key
    end

    def private_key : Bytes
      @key_pair.private_key
    end

    def signed? : Bool
      !@signature.nil?
    end

    # The signed-prekey signature input: the DJB key type byte followed by the
    # public key, signed with the device identity key (libsignal's
    # KeyPair.CreateSignedPreKey).
    def self.signature_input(public_key : Bytes) : Bytes
      input = Bytes.new(1 + public_key.size)
      input[0] = DJB_TYPE
      input[1, public_key.size].copy_from(public_key)
      input
    end

    def self.generate(id : UInt32) : self
      new(id, Crypto::Curve25519KeyPair.generate)
    end

    def self.generate_signed(id : UInt32, identity_key : Crypto::Curve25519KeyPair) : self
      key_pair = Crypto::Curve25519KeyPair.generate
      signature = Crypto::XEdDSA.sign(identity_key.private_key, signature_input(key_pair.public_key))
      new(id, key_pair, signature)
    end

    # Prekey ids travel as the low three bytes of their big-endian uint32.
    def wire_id : Bytes
      bytes = Bytes.new(4)
      IO::ByteFormat::BigEndian.encode(@id, bytes)
      bytes[1, 3]
    end

    def to_json_value : JSON::Any
      payload = JSON.build do |json|
        json.object do
          json.field "id", @id.to_s
          json.field "private", Base64.strict_encode(@key_pair.private_key)
          json.field "public", Base64.strict_encode(@key_pair.public_key)
          json.field "signature", @signature.try { |value| Base64.strict_encode(value) }
        end
      end
      JSON.parse(payload)
    end

    def self.from_json_value(value : JSON::Any) : self?
      return nil if value.raw.nil?
      id = value["id"]?.try(&.as_s.to_u32)
      private_key = decode(value["private"]?)
      public_key = decode(value["public"]?)
      return nil unless id && private_key && public_key
      signature = decode(value["signature"]?)
      new(id, Crypto::Curve25519KeyPair.new(private_key, public_key), signature)
    rescue
      nil
    end

    private def self.decode(value : JSON::Any?) : Bytes?
      value.try { |raw| Base64.decode(raw.as_s) }
    rescue
      nil
    end
  end
end

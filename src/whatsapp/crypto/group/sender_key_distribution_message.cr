require "./../../proto/writer"
require "./../../proto/handshake"
require "../curve25519"

module WhatsApp
  module Crypto
    module Group
      # Libsignal's SenderKeyDistributionMessageSerializer prefixes the
      # protobuf body with the ASCII version string "3"; see
      # protocol/SenderKeyDistributionMessage.go and
      # serialize/ProtoBufferSerializer.go. SigningKey is ecc key serialization:
      # the Curve25519 type byte (0x05) followed by its 32-byte public key.
      class SenderKeyDistributionMessage
        VERSION_PREFIX  = 0x33_u8
        CURVE25519_TYPE = 0x05_u8

        getter id : UInt32
        getter iteration : UInt32
        getter chain_key : Bytes
        getter signing_public_key : Bytes

        def initialize(@id : UInt32, @iteration : UInt32, chain_key : Bytes, signing_public_key : Bytes)
          validate_key(chain_key, "sender chain key")
          validate_key(signing_public_key, "sender signing public key")
          @chain_key = chain_key.dup
          @signing_public_key = signing_public_key.dup
        end

        def serialize : Bytes
          encoded_key = Bytes.new(33)
          encoded_key[0] = CURVE25519_TYPE
          encoded_key[1, 32].copy_from(@signing_public_key)
          body = Proto::Writer.new
            .uint(1, @id.to_u64)
            .uint(2, @iteration.to_u64)
            .raw(3, @chain_key)
            .raw(4, encoded_key)
            .bytes
          prefixed(body)
        end

        def self.deserialize(encoded : Bytes) : self
          raise ArgumentError.new("sender-key distribution message is truncated") if encoded.empty?
          raise ArgumentError.new("unsupported sender-key distribution version") unless encoded[0] == VERSION_PREFIX

          id = nil.as(UInt32?)
          iteration = nil.as(UInt32?)
          chain_key = nil.as(Bytes?)
          signing_public_key = nil.as(Bytes?)
          reader = Proto::Reader.new(encoded[1, encoded.size - 1])
          reader.each_field do |field, wire|
            case field
            when 1, 2
              raise ArgumentError.new("sender-key distribution counter has invalid wire type") unless wire == 0
              value = reader.uint_field
              raise ArgumentError.new("sender-key distribution counter overflows uint32") if value > UInt32::MAX
              if field == 1
                id = value.to_u32
              else
                iteration = value.to_u32
              end
            when 3, 4
              raise ArgumentError.new("sender-key distribution bytes have invalid wire type") unless wire == 2
              value = reader.bytes_field
              if field == 3
                chain_key = value
              else
                signing_public_key = decode_key(value)
              end
            else
              reader.skip(wire)
            end
          end

          new(
            id || raise(ArgumentError.new("sender-key distribution is missing id")),
            iteration || raise(ArgumentError.new("sender-key distribution is missing iteration")),
            chain_key || raise(ArgumentError.new("sender-key distribution is missing chain key")),
            signing_public_key || raise(ArgumentError.new("sender-key distribution is missing signing key")),
          )
        end

        private def self.decode_key(encoded : Bytes) : Bytes
          unless encoded.size == 33 && encoded[0] == CURVE25519_TYPE
            raise ArgumentError.new("sender-key distribution signing key is not a serialized Curve25519 key")
          end
          encoded[1, 32].dup
        end

        private def validate_key(key : Bytes, name : String) : Nil
          raise ArgumentError.new("#{name} must be 32 bytes") unless key.size == 32
        end

        private def prefixed(body : Bytes) : Bytes
          encoded = Bytes.new(body.size + 1)
          encoded[0] = VERSION_PREFIX
          encoded[1, body.size].copy_from(body)
          encoded
        end
      end
    end
  end
end

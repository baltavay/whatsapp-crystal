require "./../../proto/writer"
require "./../../proto/handshake"

module WhatsApp
  module Crypto
    module Group
      # SenderKeyMessage's unsigned Serialize and signed SignedSerialize come
      # from protocol/SenderKeyMessage.go; the protobuf fields themselves come
      # from serialize/WhisperTextProtocol.proto. The serializer adds ASCII
      # version "3" before the protobuf and appends the 64-byte signature after
      # it (serialize/ProtoBufferSerializer.go), not as a protobuf field.
      class SenderKeyMessage
        VERSION_PREFIX = 0x33_u8
        SIGNATURE_SIZE =      64

        getter id : UInt32
        getter iteration : UInt32
        getter ciphertext : Bytes
        getter signature : Bytes

        def initialize(@id : UInt32, @iteration : UInt32, ciphertext : Bytes, signature : Bytes)
          raise ArgumentError.new("sender-key ciphertext must not be empty") if ciphertext.empty?
          raise ArgumentError.new("sender-key signature must be 64 bytes") unless signature.size == SIGNATURE_SIZE
          @ciphertext = ciphertext.dup
          @signature = signature.dup
        end

        def unsigned_serialize : Bytes
          self.class.unsigned_body(@id, @iteration, @ciphertext)
        end

        def serialize : Bytes
          unsigned = unsigned_serialize
          encoded = Bytes.new(unsigned.size + SIGNATURE_SIZE)
          encoded[0, unsigned.size].copy_from(unsigned)
          encoded[unsigned.size, SIGNATURE_SIZE].copy_from(@signature)
          encoded
        end

        def self.unsigned_body(id : UInt32, iteration : UInt32, ciphertext : Bytes) : Bytes
          raise ArgumentError.new("sender-key ciphertext must not be empty") if ciphertext.empty?
          body = Proto::Writer.new
            .uint(1, id.to_u64)
            .uint(2, iteration.to_u64)
            .raw(3, ciphertext)
            .bytes
          encoded = Bytes.new(body.size + 1)
          encoded[0] = VERSION_PREFIX
          encoded[1, body.size].copy_from(body)
          encoded
        end

        def self.deserialize(encoded : Bytes) : self
          minimum = 1 + 1 + 1 + 1 + 1 + SIGNATURE_SIZE
          raise ArgumentError.new("sender-key message is truncated") if encoded.size < minimum
          raise ArgumentError.new("unsupported sender-key message version") unless encoded[0] == VERSION_PREFIX

          protobuf_end = encoded.size - SIGNATURE_SIZE
          id = nil.as(UInt32?)
          iteration = nil.as(UInt32?)
          ciphertext = nil.as(Bytes?)
          reader = Proto::Reader.new(encoded[1, protobuf_end - 1])
          reader.each_field do |field, wire|
            case field
            when 1, 2
              raise ArgumentError.new("sender-key message counter has invalid wire type") unless wire == 0
              value = reader.uint_field
              raise ArgumentError.new("sender-key message counter overflows uint32") if value > UInt32::MAX
              if field == 1
                id = value.to_u32
              else
                iteration = value.to_u32
              end
            when 3
              raise ArgumentError.new("sender-key ciphertext has invalid wire type") unless wire == 2
              ciphertext = reader.bytes_field
            else
              reader.skip(wire)
            end
          end

          new(
            id || raise(ArgumentError.new("sender-key message is missing id")),
            iteration || raise(ArgumentError.new("sender-key message is missing iteration")),
            ciphertext || raise(ArgumentError.new("sender-key message is missing ciphertext")),
            encoded[protobuf_end, SIGNATURE_SIZE],
          )
        end
      end
    end
  end
end

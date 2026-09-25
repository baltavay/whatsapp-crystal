require "random/secure"
require "./../../proto/writer"
require "./../../proto/handshake"
require "../curve25519"

module WhatsApp
  module Crypto
    module Group
      # Sender-key chain state mirrors libsignal's SenderKeyState and
      # SenderChainKey (groups/state/record/SenderKeyState.go and
      # groups/ratchet/SenderChainKey.go). `serialize` follows the
      # SenderKeyRecordStructure / SenderKeyStateStructure schema in
      # serialize/LocalStorageProtocol.proto.
      class SenderKey
        getter id : UInt32
        getter iteration : UInt32
        getter chain_key : Bytes
        getter signing_public_key : Bytes
        getter signing_private_key : Bytes?
        getter skipped_message_keys : Hash(UInt32, Bytes)

        def initialize(
          @id : UInt32,
          @iteration : UInt32,
          chain_key : Bytes,
          signing_public_key : Bytes,
          signing_private_key : Bytes? = nil,
        )
          validate_key(chain_key, "sender chain key")
          validate_key(signing_public_key, "sender signing public key")
          if private_key = signing_private_key
            validate_key(private_key, "sender signing private key")
          end
          @chain_key = chain_key.dup
          @signing_public_key = signing_public_key.dup
          @signing_private_key = signing_private_key.try(&.dup)
          @skipped_message_keys = Hash(UInt32, Bytes).new
        end

        def self.generate(id : UInt32) : self
          pair = Curve25519KeyPair.generate
          new(id, 0_u32, Random::Secure.random_bytes(32), pair.public_key, pair.private_key)
        end

        # Build a receiver-side record from an incoming distribution message.
        def self.from_distribution(message : SenderKeyDistributionMessage) : self
          new(message.id, message.iteration, message.chain_key, message.signing_public_key)
        end

        def signing_key_pair : Curve25519KeyPair?
          private_key = @signing_private_key
          private_key ? Curve25519KeyPair.new(private_key, @signing_public_key) : nil
        end

        def serialize : Bytes
          state = Proto::Writer.new
          state.uint(1, @id.to_u64)

          chain = Proto::Writer.new
          chain.uint(1, @iteration.to_u64).raw(2, @chain_key)
          state.message(2, chain)

          signing = Proto::Writer.new
          signing.raw(1, Bytes[5_u8] + @signing_public_key)
          if private_key = @signing_private_key
            signing.raw(2, private_key)
          end
          state.message(3, signing)

          @skipped_message_keys.each do |iteration, seed|
            skipped = Proto::Writer.new
            skipped.uint(1, iteration.to_u64).raw(2, seed)
            state.message(4, skipped)
          end

          Proto::Writer.new.message(1, state).bytes
        end

        def self.from_serialized(encoded : Bytes) : self
          outer = Proto::Reader.new(encoded)
          state_bytes = nil.as(Bytes?)
          outer.each_field do |field, wire|
            if field == 1
              raise ArgumentError.new("sender-key record state has invalid wire type") unless wire == 2
              state_bytes = outer.bytes_field
            else
              outer.skip(wire)
            end
          end
          state = state_bytes || raise ArgumentError.new("sender-key record has no state")

          id = nil.as(UInt32?)
          iteration = nil.as(UInt32?)
          chain_key = nil.as(Bytes?)
          signing_public_key = nil.as(Bytes?)
          signing_private_key = nil.as(Bytes?)
          skipped_keys = [] of Tuple(UInt32, Bytes)
          reader = Proto::Reader.new(state)
          reader.each_field do |field, wire|
            case field
            when 1
              raise ArgumentError.new("sender-key id has invalid wire type") unless wire == 0
              id = uint32(reader.uint_field, "sender-key id")
            when 2
              raise ArgumentError.new("sender chain state has invalid wire type") unless wire == 2
              iteration, chain_key = decode_chain(reader.bytes_field)
            when 3
              raise ArgumentError.new("sender signing state has invalid wire type") unless wire == 2
              signing_public_key, signing_private_key = decode_signing(reader.bytes_field)
            when 4
              raise ArgumentError.new("skipped message key has invalid wire type") unless wire == 2
              skipped_keys << decode_skipped(reader.bytes_field)
            else
              reader.skip(wire)
            end
          end

          result = new(
            id || raise(ArgumentError.new("sender-key record is missing id")),
            iteration || raise(ArgumentError.new("sender-key record is missing iteration")),
            chain_key || raise(ArgumentError.new("sender-key record is missing chain key")),
            signing_public_key || raise(ArgumentError.new("sender-key record is missing signing public key")),
            signing_private_key
          )
          skipped_keys.each { |entry| result.remember_message_key(entry[0], entry[1]) }
          result
        end

        def replace_chain!(iteration : UInt32, chain_key : Bytes) : Nil
          validate_key(chain_key, "sender chain key")
          @iteration = iteration
          @chain_key = chain_key.dup
        end

        def remember_message_key(iteration : UInt32, seed : Bytes) : Nil
          @skipped_message_keys[iteration] = seed.dup
        end

        def take_message_key(iteration : UInt32) : Bytes?
          @skipped_message_keys.delete(iteration)
        end

        private def self.decode_chain(encoded : Bytes) : Tuple(UInt32, Bytes)
          iteration = nil.as(UInt32?)
          seed = nil.as(Bytes?)
          reader = Proto::Reader.new(encoded)
          reader.each_field do |field, wire|
            case field
            when 1
              raise ArgumentError.new("sender chain iteration has invalid wire type") unless wire == 0
              iteration = uint32(reader.uint_field, "sender chain iteration")
            when 2
              raise ArgumentError.new("sender chain seed has invalid wire type") unless wire == 2
              seed = reader.bytes_field
            else
              reader.skip(wire)
            end
          end
          {
            iteration || raise(ArgumentError.new("sender chain is missing iteration")),
            seed || raise(ArgumentError.new("sender chain is missing seed")),
          }
        end

        private def self.decode_signing(encoded : Bytes) : Tuple(Bytes, Bytes?)
          public_key = nil.as(Bytes?)
          private_key = nil.as(Bytes?)
          reader = Proto::Reader.new(encoded)
          reader.each_field do |field, wire|
            case field
            when 1, 2
              raise ArgumentError.new("sender signing key has invalid wire type") unless wire == 2
              value = reader.bytes_field
              if field == 1
                public_key = decode_curve_key(value)
              else
                private_key = value
              end
            else
              reader.skip(wire)
            end
          end
          {public_key || raise(ArgumentError.new("sender signing state is missing public key")), private_key}
        end

        private def self.decode_skipped(encoded : Bytes) : Tuple(UInt32, Bytes)
          iteration = nil.as(UInt32?)
          seed = nil.as(Bytes?)
          reader = Proto::Reader.new(encoded)
          reader.each_field do |field, wire|
            case field
            when 1
              raise ArgumentError.new("skipped message iteration has invalid wire type") unless wire == 0
              iteration = uint32(reader.uint_field, "skipped message iteration")
            when 2
              raise ArgumentError.new("skipped message seed has invalid wire type") unless wire == 2
              seed = reader.bytes_field
            else
              reader.skip(wire)
            end
          end
          {
            iteration || raise(ArgumentError.new("skipped message key is missing iteration")),
            seed || raise(ArgumentError.new("skipped message key is missing seed")),
          }
        end

        private def self.decode_curve_key(encoded : Bytes) : Bytes
          unless encoded.size == 33 && encoded[0] == 5_u8
            raise ArgumentError.new("sender signing key is not a serialized Curve25519 key")
          end
          encoded[1, 32].dup
        end

        private def self.uint32(value : UInt64, name : String) : UInt32
          raise ArgumentError.new("#{name} overflows uint32") if value > UInt32::MAX
          value.to_u32
        end

        private def validate_key(key : Bytes, name : String) : Nil
          raise ArgumentError.new("#{name} must be 32 bytes") unless key.size == 32
        end
      end
    end
  end
end

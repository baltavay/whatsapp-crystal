require "time"
require "../proto/handshake"
require "./curve25519"

module WhatsApp
  module Crypto
    # WA's Noise certificate chain is protobuf encoded inside the encrypted
    # Noise server hello payload. Verification is kept separate from transport
    # so the handshake cannot silently treat an unverified key as trusted.
    class NoiseCertificate
      ROOT_PUBLIC_KEY = Bytes[
        0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71,
        0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
        0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c,
        0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
      ]
      ROOT_ISSUER_SERIAL = 0_u64

      struct Details
        getter serial : UInt64
        getter issuer_serial : UInt64
        getter key : Bytes
        getter not_before : UInt64
        getter not_after : UInt64

        def initialize(@serial, @issuer_serial, key : Bytes, @not_before, @not_after)
          raise ArgumentError.new("Noise certificate key must be 32 bytes") unless key.size == 32
          @key = key.dup
        end
      end

      struct Entry
        getter details : Bytes
        getter signature : Bytes
        getter parsed : Details

        def initialize(@details : Bytes, @signature : Bytes)
          raise ArgumentError.new("Noise certificate signature must be 64 bytes") unless @signature.size == 64
          @parsed = parse_details(@details)
        end

        private def parse_details(encoded : Bytes) : Details
          reader = Proto::Reader.new(encoded)
          serial = 0_u64
          issuer = 0_u64
          key = Bytes.new(0)
          not_before = 0_u64
          not_after = 0_u64
          reader.each_field do |field, wire_type|
            case field
            when 1, 2, 4, 5
              raise ArgumentError.new("Noise certificate details field #{field} has invalid wire type") unless wire_type == 0
              value = reader.uint_field
              case field
              when 1 then serial = value
              when 2 then issuer = value
              when 4 then not_before = value
              when 5 then not_after = value
              end
            when 3
              raise ArgumentError.new("Noise certificate key has invalid wire type") unless wire_type == 2
              key = reader.bytes_field
            else
              reader.skip(wire_type)
            end
          end
          raise ArgumentError.new("Noise certificate details are incomplete") if key.empty? || not_before == 0 || not_after == 0
          Details.new(serial, issuer, key, not_before, not_after)
        end
      end

      getter leaf : Entry
      getter intermediate : Entry

      def initialize(@leaf : Entry, @intermediate : Entry)
      end

      def self.decode(encoded : Bytes) : self
        reader = Proto::Reader.new(encoded)
        leaf = nil.as(Entry?)
        intermediate = nil.as(Entry?)
        reader.each_field do |field, wire_type|
          next unless field == 1 || field == 2
          raise ArgumentError.new("Noise certificate chain field has invalid wire type") unless wire_type == 2
          nested = reader.bytes_field
          entry = decode_entry(nested)
          if field == 1
            leaf = entry
          else
            intermediate = entry
          end
        end
        new(leaf || raise(ArgumentError.new("Noise certificate chain has no leaf")), intermediate || raise(ArgumentError.new("Noise certificate chain has no intermediate")))
      end

      def self.verify(encoded : Bytes, server_static : Bytes) : Bool
        return false unless server_static.size == 32
        chain = decode(encoded)
        return false unless XEdDSA.verify(ROOT_PUBLIC_KEY, chain.intermediate.details, chain.intermediate.signature)
        intermediate = chain.intermediate.parsed
        return false unless intermediate.issuer_serial == ROOT_ISSUER_SERIAL
        return false unless XEdDSA.verify(intermediate.key, chain.leaf.details, chain.leaf.signature)
        leaf = chain.leaf.parsed
        return false unless leaf.issuer_serial == intermediate.serial
        return false unless leaf.key == server_static
        now = Time.utc.to_unix.to_u64
        now >= intermediate.not_before && now <= intermediate.not_after && now >= leaf.not_before && now <= leaf.not_after
      rescue ArgumentError
        false
      end

      private def self.decode_entry(encoded : Bytes) : Entry
        reader = Proto::Reader.new(encoded)
        details = nil.as(Bytes?)
        signature = nil.as(Bytes?)
        reader.each_field do |field, wire_type|
          next unless field == 1 || field == 2
          raise ArgumentError.new("Noise certificate entry has invalid wire type") unless wire_type == 2
          value = reader.bytes_field
          if field == 1
            details = value
          else
            signature = value
          end
        end
        Entry.new(details || Bytes.new(0), signature || Bytes.new(0))
      end
    end
  end
end

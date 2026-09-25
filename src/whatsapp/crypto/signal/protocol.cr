require "openssl/cipher"
require "openssl/hmac"
require "base64"
require "json"
require "random/secure"
require "../../proto/writer"

module WhatsApp
  module Crypto
    module Signal
      VERSION             =      3_u8
      WIRE_VERSION        =   0x33_u8
      MAC_LENGTH          =         8
      MAX_FUTURE_MESSAGES = 2_000_u32
      MAX_SKIPPED_KEYS    =     2_000

      # Libsignal's protocol.SignalAddress is the (name, device ID) identity
      # used to scope sessions. This port uses a compact value object.
      struct Address
        getter name : String
        getter device_id : UInt32

        def initialize(@name : String, device_id : UInt32 | Int32)
          raise ArgumentError.new("device ID must be nonnegative") if device_id < 0
          @device_id = device_id.to_u32
        end

        def key : String
          "#{@name}:#{@device_id}"
        end
      end

      struct PreKeyBundle
        getter registration_id : UInt32
        getter device_id : UInt32
        getter prekey_id : UInt32
        getter prekey_public : Bytes
        getter signed_prekey_id : UInt32
        getter signed_prekey_public : Bytes
        getter signed_prekey_signature : Bytes
        getter identity_key : Bytes

        def initialize(registration_id : UInt32 | Int32, device_id : UInt32 | Int32,
                       prekey_id : UInt32 | Int32, prekey_public : Bytes,
                       signed_prekey_id : UInt32 | Int32, signed_prekey_public : Bytes,
                       signed_prekey_signature : Bytes, identity_key : Bytes)
          @registration_id = registration_id.to_u32
          @device_id = device_id.to_u32
          @prekey_id = prekey_id.to_u32
          @signed_prekey_id = signed_prekey_id.to_u32
          raise ArgumentError.new("Curve25519 prekey public keys must be 32 bytes") unless prekey_public.size == 32 && signed_prekey_public.size == 32 && identity_key.size == 32
          raise ArgumentError.new("signed prekey signature must be 64 bytes") unless signed_prekey_signature.size == 64
          @prekey_public = prekey_public.dup
          @signed_prekey_public = signed_prekey_public.dup
          @signed_prekey_signature = signed_prekey_signature.dup
          @identity_key = identity_key.dup
        end
      end

      # Type tag and exact versioned bytes used by protocol.CiphertextMessage.
      struct CiphertextMessage
        getter type : Symbol
        getter serialized : Bytes

        def initialize(@type : Symbol, serialized : Bytes)
          raise ArgumentError.new("ciphertext message type must be :prekey or :signal") unless @type == :prekey || @type == :signal
          @serialized = serialized.dup
        end

        def serialize : Bytes
          @serialized.dup
        end

        def self.parse(serialized : Bytes) : self
          type = Protocol.prekey_message?(serialized) ? :prekey : :signal
          Protocol.validate_outer(serialized, type)
          new(type, serialized)
        end
      end

      struct MessageKeys
        getter cipher_key : Bytes
        getter mac_key : Bytes
        getter iv : Bytes

        def initialize(@cipher_key : Bytes, @mac_key : Bytes, @iv : Bytes)
        end
      end

      private struct ProtoField
        getter bytes : Bytes?
        getter integer : UInt64?

        def initialize(@bytes : Bytes? = nil, @integer : UInt64? = nil)
        end
      end

      # Field numbers/outer version and canonical reserialization follow
      # libsignal serialize/WhisperTextProtocol.proto and serialize/ProtoBufferSerializer.go.
      private module Protocol
        extend self

        struct SignalData
          getter ratchet_key : Bytes
          getter counter : UInt32
          getter previous_counter : UInt32
          getter ciphertext : Bytes
          getter mac : Bytes

          def initialize(@ratchet_key : Bytes, @counter : UInt32, @previous_counter : UInt32, @ciphertext : Bytes, @mac : Bytes)
          end
        end

        struct PreKeyData
          getter registration_id : UInt32
          getter prekey_id : UInt32?
          getter signed_prekey_id : UInt32
          getter base_key : Bytes
          getter identity_key : Bytes
          getter signal : SignalData

          def initialize(@registration_id : UInt32, @prekey_id : UInt32?, @signed_prekey_id : UInt32,
                         @base_key : Bytes, @identity_key : Bytes, @signal : SignalData)
          end
        end

        def prekey_message?(bytes : Bytes) : Bool
          bytes.size >= 2 && bytes[0] == WIRE_VERSION && begin
            fields = parse_fields(bytes[1, bytes.size - 1])
            field_bytes(fields, 2).try { |candidate| candidate.size == 33 && candidate[0] == 5_u8 } || false
          rescue WhatsApp::Error
            false
          end
        end

        def validate_outer(bytes : Bytes, type : Symbol) : Nil
          raise WhatsApp::Error.new("Signal ciphertext is too short") if bytes.size < 2
          raise WhatsApp::Error.new("unsupported Signal message version") unless bytes[0] == WIRE_VERSION
          if type == :signal
            raise WhatsApp::Error.new("Signal message is too short") if bytes.size < 1 + MAC_LENGTH + 1
          end
        end

        def encode_signal(ratchet_key : Bytes, counter : UInt32, previous_counter : UInt32,
                          ciphertext : Bytes, mac_key : Bytes, sender_identity : Bytes,
                          receiver_identity : Bytes) : Bytes
          proto = encode_signal_proto(ratchet_key, counter, previous_counter, ciphertext)
          # SignalMessage.go:getMac prepends ASCII version "3"; the serialized wire
          # version byte itself is the high/low version pair 0x33.
          authenticated = identity_wire(sender_identity) + identity_wire(receiver_identity) + "3".to_slice + proto
          mac = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, mac_key, authenticated)[0, MAC_LENGTH]
          Bytes[WIRE_VERSION] + proto + mac
        end

        def decode_signal(bytes : Bytes) : SignalData
          validate_outer(bytes, :signal)
          encoded = bytes[1, bytes.size - 1 - MAC_LENGTH]
          fields = parse_fields(encoded)
          ratchet = required_bytes(fields, 1, "ratchetKey")
          validate_serialized_key!(ratchet)
          counter = required_uint(fields, 2, "counter").to_u32
          previous = required_uint(fields, 3, "previousCounter").to_u32
          body = required_bytes(fields, 4, "ciphertext")
          mac = bytes[bytes.size - MAC_LENGTH, MAC_LENGTH]
          SignalData.new(ratchet[1, 32].dup, counter, previous, body, mac.dup)
        end

        def encode_prekey(registration_id : UInt32, prekey_id : UInt32?, signed_prekey_id : UInt32,
                          base_key : Bytes, identity_key : Bytes, inner_signal : Bytes) : Bytes
          writer = WhatsApp::Proto::Writer.new
          writer.uint(1, prekey_id.not_nil!.to_u64) if prekey_id
          writer.raw(2, serialize_key(base_key))
          writer.raw(3, identity_wire(identity_key))
          writer.raw(4, inner_signal)
          writer.uint(5, registration_id.to_u64)
          writer.uint(6, signed_prekey_id.to_u64)
          Bytes[WIRE_VERSION] + writer.bytes
        end

        def decode_prekey(bytes : Bytes) : PreKeyData
          validate_outer(bytes, :prekey)
          fields = parse_fields(bytes[1, bytes.size - 1])
          base = required_bytes(fields, 2, "baseKey")
          identity = required_bytes(fields, 3, "identityKey")
          validate_serialized_key!(base)
          validate_serialized_key!(identity)
          inner = required_bytes(fields, 4, "message")
          signal = decode_signal(inner)
          prekey = optional_uint(fields, 1).try(&.to_u32)
          PreKeyData.new(required_uint(fields, 5, "registrationId").to_u32, prekey,
            required_uint(fields, 6, "signedPreKeyId").to_u32, base[1, 32].dup,
            identity[1, 32].dup, signal)
        end

        def verify_mac!(data : SignalData, mac_key : Bytes, sender_identity : Bytes, receiver_identity : Bytes) : Nil
          proto = encode_signal_proto(data.ratchet_key, data.counter, data.previous_counter, data.ciphertext)
          authenticated = identity_wire(sender_identity) + identity_wire(receiver_identity) + "3".to_slice + proto
          expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, mac_key, authenticated)[0, MAC_LENGTH]
          raise WhatsApp::Error.new("invalid Signal message MAC") unless constant_time_equal?(expected, data.mac)
        end

        def encode_signal_proto(ratchet_key : Bytes, counter : UInt32, previous_counter : UInt32, ciphertext : Bytes) : Bytes
          writer = WhatsApp::Proto::Writer.new
          writer.raw(1, serialize_key(ratchet_key))
          writer.uint(2, counter.to_u64)
          writer.uint(3, previous_counter.to_u64)
          writer.raw(4, ciphertext)
          writer.bytes.dup
        end

        def identity_wire(identity : Bytes) : Bytes
          serialize_key(identity)
        end

        def serialize_key(key : Bytes) : Bytes
          raise ArgumentError.new("Curve25519 public key must be 32 bytes") unless key.size == 32
          encoded = Bytes.new(33)
          encoded[0] = 5_u8
          encoded[1, 32].copy_from(key)
          encoded
        end

        private def validate_serialized_key!(key : Bytes) : Nil
          raise WhatsApp::Error.new("invalid Curve25519 key encoding") unless key.size == 33 && key[0] == 5_u8
        end

        private def parse_fields(bytes : Bytes) : Hash(Int32, Array(ProtoField))
          fields = Hash(Int32, Array(ProtoField)).new
          offset = 0
          while offset < bytes.size
            tag = read_varint(bytes, offset)
            offset = tag[1]
            field_number = (tag[0] >> 3).to_i
            wire_type = (tag[0] & 7).to_i
            raise WhatsApp::Error.new("invalid protobuf field number") if field_number <= 0
            field = case wire_type
                    when 0
                      value = read_varint(bytes, offset)
                      offset = value[1]
                      ProtoField.new(integer: value[0])
                    when 1
                      raise WhatsApp::Error.new("truncated protobuf fixed64") if bytes.size - offset < 8
                      offset += 8
                      next
                    when 2
                      size = read_varint(bytes, offset)
                      offset = size[1]
                      length = size[0].to_i
                      raise WhatsApp::Error.new("truncated protobuf field") if length < 0 || bytes.size - offset < length
                      value = bytes[offset, length].dup
                      offset += length
                      ProtoField.new(bytes: value)
                    when 5
                      raise WhatsApp::Error.new("truncated protobuf fixed32") if bytes.size - offset < 4
                      offset += 4
                      next
                    else
                      raise WhatsApp::Error.new("unsupported protobuf wire type #{wire_type}")
                    end
            (fields[field_number] ||= [] of ProtoField) << field
          end
          fields
        end

        private def read_varint(bytes : Bytes, offset : Int32) : Tuple(UInt64, Int32)
          result = 0_u64
          shift = 0
          while offset < bytes.size && shift < 70
            byte = bytes[offset]
            offset += 1
            result |= ((byte & 0x7f).to_u64 << shift) if shift < 64
            return {result, offset} if (byte & 0x80) == 0
            shift += 7
          end
          raise WhatsApp::Error.new("invalid or truncated protobuf varint")
        end

        private def required_bytes(fields : Hash(Int32, Array(ProtoField)), field : Int32, label : String) : Bytes
          value = fields[field]?.try(&.first?).try(&.bytes)
          value || raise WhatsApp::Error.new("missing Signal protobuf field #{label}")
        end

        private def required_uint(fields : Hash(Int32, Array(ProtoField)), field : Int32, label : String) : UInt64
          value = fields[field]?.try(&.first?).try(&.integer)
          value || raise WhatsApp::Error.new("missing Signal protobuf field #{label}")
        end

        private def optional_uint(fields : Hash(Int32, Array(ProtoField)), field : Int32) : UInt64?
          fields[field]?.try(&.first?).try(&.integer)
        end

        private def field_bytes(fields : Hash(Int32, Array(ProtoField)), field : Int32) : Bytes?
          fields[field]?.try(&.first?).try(&.bytes)
        end

        private def constant_time_equal?(left : Bytes, right : Bytes) : Bool
          return false unless left.size == right.size
          diff = 0_u8
          left.size.times { |i| diff |= left[i] ^ right[i] }
          diff == 0
        end
      end
    end
  end
end

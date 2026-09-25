require "./writer"
require "./handshake"

module WhatsApp
  module Proto
    module ADV
      struct DeviceIdentity
        getter raw_id : UInt64
        getter timestamp : UInt64
        getter key_index : UInt64
        getter account_type : UInt64
        getter device_type : UInt64

        def initialize(@raw_id : UInt64, @timestamp : UInt64, @key_index : UInt64, @account_type : UInt64, @device_type : UInt64)
        end

        def encode : Bytes
          Writer.new
            .uint(1, @raw_id)
            .uint(2, @timestamp)
            .uint(3, @key_index)
            .uint(4, @account_type)
            .uint(5, @device_type)
            .bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          raw_id = 0_u64
          timestamp = 0_u64
          key_index = 0_u64
          account_type = 0_u64
          device_type = 0_u64

          reader.each_field do |field, wire_type|
            case field
            when 1, 2, 3, 4, 5
              raise WhatsApp::Error.new("ADV device identity field #{field} has invalid wire type") unless wire_type == 0
              value = reader.uint_field
              case field
              when 1 then raw_id = value
              when 2 then timestamp = value
              when 3 then key_index = value
              when 4 then account_type = value
              when 5 then device_type = value
              end
            else
              reader.skip(wire_type)
            end
          end

          new(raw_id, timestamp, key_index, account_type, device_type)
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid ADV device identity protobuf: #{ex.message}")
        end
      end

      class SignedDeviceIdentity
        property details : Bytes
        property account_signature_key : Bytes?
        property account_signature : Bytes?
        property device_signature : Bytes?

        def initialize(@details : Bytes = Bytes.empty, @account_signature_key : Bytes? = nil, @account_signature : Bytes? = nil, @device_signature : Bytes? = nil)
        end

        def encode : Bytes
          writer = Writer.new
          writer.raw(1, @details) unless @details.empty?
          if signature_key = @account_signature_key
            writer.raw(2, signature_key) unless signature_key.empty?
          end
          if signature = @account_signature
            writer.raw(3, signature) unless signature.empty?
          end
          if signature = @device_signature
            writer.raw(4, signature) unless signature.empty?
          end
          writer.bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          details = Bytes.empty
          account_signature_key = nil.as(Bytes?)
          account_signature = nil.as(Bytes?)
          device_signature = nil.as(Bytes?)

          reader.each_field do |field, wire_type|
            case field
            when 1, 2, 3, 4
              raise WhatsApp::Error.new("ADV signed device identity field #{field} has invalid wire type") unless wire_type == 2
              value = reader.bytes_field
              case field
              when 1
                details = value
              when 2
                account_signature_key = value
              when 3
                account_signature = value
              when 4
                device_signature = value
              end
            else
              reader.skip(wire_type)
            end
          end

          new(details, account_signature_key, account_signature, device_signature)
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid ADV signed device identity protobuf: #{ex.message}")
        end
      end

      class SignedDeviceIdentityHMAC
        property details : Bytes
        property hmac : Bytes
        property account_type : UInt32

        def initialize(@details : Bytes = Bytes.empty, @hmac : Bytes = Bytes.empty, @account_type : UInt32 = 0_u32)
        end

        def encode : Bytes
          writer = Writer.new
          writer.raw(1, @details) unless @details.empty?
          writer.raw(2, @hmac) unless @hmac.empty?
          writer.uint(3, @account_type.to_u64)
          writer.bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          details = Bytes.empty
          hmac = Bytes.empty
          account_type = 0_u32

          reader.each_field do |field, wire_type|
            case field
            when 1, 2
              raise WhatsApp::Error.new("ADV signed device identity HMAC field #{field} has invalid wire type") unless wire_type == 2
              value = reader.bytes_field
              if field == 1
                details = value
              else
                hmac = value
              end
            when 3
              raise WhatsApp::Error.new("ADV signed device identity HMAC field 3 has invalid wire type") unless wire_type == 0
              value = reader.uint_field
              raise WhatsApp::Error.new("ADV signed device identity HMAC account type exceeds uint32") if value > UInt32::MAX
              account_type = value.to_u32
            else
              reader.skip(wire_type)
            end
          end

          new(details, hmac, account_type)
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid ADV signed device identity HMAC protobuf: #{ex.message}")
        end
      end
    end
  end
end

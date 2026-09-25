module WhatsApp
  module Proto
    # Small protobuf wire writer for the message envelopes used by this client.
    # It intentionally models wire primitives rather than generated classes.
    class Writer
      getter io : IO::Memory

      def initialize
        @io = IO::Memory.new
      end

      def bytes : Bytes
        @io.to_slice
      end

      def string(field : Int32, value : String) : self
        raw(field, value.to_slice)
      end

      def raw(field : Int32, value : Bytes) : self
        key(field, 2)
        varint(value.size.to_u64)
        @io.write(value)
        self
      end

      def uint(field : Int32, value : UInt64) : self
        key(field, 0)
        varint(value)
        self
      end

      def bool(field : Int32, value : Bool) : self
        uint(field, value ? 1_u64 : 0_u64)
      end

      # Wire type 5. WhatsApp uses it for ClientPayload.sessionID.
      def fixed32(field : Int32, value : UInt32) : self
        key(field, 5)
        @io.write_bytes(value, IO::ByteFormat::LittleEndian)
        self
      end

      def message(field : Int32, nested : Writer) : self
        raw(field, nested.bytes)
      end

      def message(field : Int32, nested : Bytes) : self
        raw(field, nested)
      end

      private def key(field : Int32, wire_type : Int32) : Nil
        varint(((field.to_u64) << 3) | wire_type.to_u64)
      end

      private def varint(value : UInt64) : Nil
        number = value
        while number >= 0x80
          @io.write_byte(((number & 0x7f) | 0x80).to_u8)
          number >>= 7
        end
        @io.write_byte(number.to_u8)
      end
    end
  end
end

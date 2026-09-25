require "compress/zlib"

module WhatsApp
  module Binary
    # Every decrypted WhatsApp frame is a flag byte followed by binary XML.
    # Bit 1 of the flag marks a zlib-compressed body; outbound nodes must carry
    # the same flag byte, otherwise the server cannot decode them.
    module Frame
      extend self

      COMPRESSED_FLAG = 2_u8

      def unpack(payload : Bytes) : Bytes
        raise Error.new("WhatsApp frame is empty") if payload.empty?
        flag = payload[0]
        body = payload[1, payload.size - 1]
        return body if (flag & COMPRESSED_FLAG) == 0
        decompress(body)
      end

      def pack(node : Bytes) : Bytes
        packed = Bytes.new(node.size + 1)
        packed[0] = 0_u8
        packed[1, node.size].copy_from(node)
        packed
      end

      private def decompress(body : Bytes) : Bytes
        Compress::Zlib::Reader.open(IO::Memory.new(body)) { |reader| reader.gets_to_end.to_slice }
      rescue ex : Compress::Zlib::Error
        raise Error.new("WhatsApp frame is not valid zlib data: #{ex.message}")
      end
    end
  end
end

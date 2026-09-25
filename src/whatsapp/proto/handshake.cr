require "./writer"

module WhatsApp
  module Proto
    MAX_HANDSHAKE_SIZE = 1 << 20

    class ClientHello
      getter ephemeral : Bytes

      def initialize(@ephemeral : Bytes)
        raise ArgumentError.new("client ephemeral key must be 32 bytes") unless @ephemeral.size == 32
      end

      def encode : Bytes
        Writer.new.raw(1, @ephemeral).bytes
      end
    end

    class ServerHello
      getter ephemeral : Bytes
      getter static : Bytes
      getter payload : Bytes

      def initialize(@ephemeral : Bytes, @static : Bytes, @payload : Bytes)
        raise ArgumentError.new("server ephemeral key must be 32 bytes") unless @ephemeral.size == 32
        raise ArgumentError.new("server static ciphertext is empty") if @static.empty?
        raise ArgumentError.new("server certificate ciphertext is empty") if @payload.empty?
      end

      def self.decode(data : Bytes) : self
        raise ArgumentError.new("server hello exceeds maximum size") if data.size > MAX_HANDSHAKE_SIZE
        reader = Reader.new(data)
        ephemeral = nil.as(Bytes?)
        static = nil.as(Bytes?)
        payload = nil.as(Bytes?)
        reader.each_field do |field, wire_type|
          if field == 1 || field == 2 || field == 3
            raise ArgumentError.new("server hello field #{field} has invalid wire type") unless wire_type == 2
            value = reader.bytes_field
            case field
            when 1 then ephemeral = value
            when 2 then static = value
            when 3 then payload = value
            end
          else
            reader.skip(wire_type)
          end
        end
        new(ephemeral || Bytes.new(0), static || Bytes.new(0), payload || Bytes.new(0))
      end
    end

    class ClientFinish
      getter static : Bytes
      getter payload : Bytes

      def initialize(@static : Bytes, @payload : Bytes)
        raise ArgumentError.new("client static ciphertext is empty") if @static.empty?
        raise ArgumentError.new("client payload ciphertext is empty") if @payload.empty?
      end

      def encode : Bytes
        Writer.new.raw(1, @static).raw(2, @payload).bytes
      end

      def self.decode(data : Bytes) : self
        raise ArgumentError.new("client finish exceeds maximum size") if data.size > MAX_HANDSHAKE_SIZE
        reader = Reader.new(data)
        static = nil.as(Bytes?)
        payload = nil.as(Bytes?)
        reader.each_field do |field, wire_type|
          if field == 1 || field == 2
            raise ArgumentError.new("client finish field #{field} has invalid wire type") unless wire_type == 2
            value = reader.bytes_field
            if field == 1
              static = value
            else
              payload = value
            end
          else
            reader.skip(wire_type)
          end
        end
        new(static || Bytes.new(0), payload || Bytes.new(0))
      end
    end

    class Handshake
      getter client_hello : ClientHello?
      getter server_hello : ServerHello?
      getter client_finish : ClientFinish?

      def initialize(@client_hello : ClientHello? = nil, @server_hello : ServerHello? = nil, @client_finish : ClientFinish? = nil)
        present = [@client_hello, @server_hello, @client_finish].count { |value| !value.nil? }
        raise ArgumentError.new("handshake must contain exactly one message") unless present == 1
      end

      def encode : Bytes
        writer = Writer.new
        if hello = @client_hello
          writer.raw(2, hello.encode)
        elsif hello = @server_hello
          nested = Writer.new.raw(1, hello.ephemeral).raw(2, hello.static).raw(3, hello.payload).bytes
          writer.raw(3, nested)
        elsif finish = @client_finish
          writer.raw(4, finish.encode)
        end
        bytes = writer.bytes
        raise ArgumentError.new("handshake exceeds maximum size") if bytes.size > MAX_HANDSHAKE_SIZE
        bytes
      end

      def self.decode(data : Bytes) : self
        raise ArgumentError.new("handshake exceeds maximum size") if data.size > MAX_HANDSHAKE_SIZE
        reader = Reader.new(data)
        client = nil.as(ClientHello?)
        server = nil.as(ServerHello?)
        finish = nil.as(ClientFinish?)
        reader.each_field do |field, wire_type|
          if field == 2 || field == 3 || field == 4
            raise ArgumentError.new("handshake field #{field} has invalid wire type") unless wire_type == 2
            nested = reader.bytes_field
            case field
            when 2
              client = decode_client_hello(nested)
            when 3
              server = ServerHello.decode(nested)
            when 4
              finish = ClientFinish.decode(nested)
            end
          else
            reader.skip(wire_type)
          end
        end
        new(client, server, finish)
      end

      private def self.decode_client_hello(data : Bytes) : ClientHello
        reader = Reader.new(data)
        ephemeral = nil.as(Bytes?)
        reader.each_field do |field, wire_type|
          if field == 1
            raise ArgumentError.new("client hello ephemeral has invalid wire type") unless wire_type == 2
            ephemeral = reader.bytes_field
          else
            reader.skip(wire_type)
          end
        end
        ClientHello.new(ephemeral || Bytes.new(0))
      end
    end

    class Reader
      def initialize(@data : Bytes)
        raise ArgumentError.new("protobuf input exceeds maximum size") if @data.size > MAX_HANDSHAKE_SIZE
        @offset = 0
      end

      def each_field(& : Int32, Int32 ->) : Nil
        until @offset >= @data.size
          key = varint
          field_number = key >> 3
          raise ArgumentError.new("protobuf field number is too large") if field_number > Int32::MAX
          field = field_number.to_i
          wire_type = (key & 7).to_i
          raise ArgumentError.new("protobuf field number must be positive") if field == 0
          yield field, wire_type
        end
      end

      def bytes_field : Bytes
        length = varint
        remaining = (@data.size - @offset).to_u64
        raise ArgumentError.new("protobuf field exceeds input") if length > remaining
        size = length.to_i
        value = @data[@offset, size].dup
        @offset += size
        value
      end

      def uint_field : UInt64
        varint
      end

      # Wire types 0 (varint), 1 (fixed64), 2 (length-delimited) and 5 (fixed32)
      # are the ones WhatsApp's payloads use.
      def skip(wire_type : Int32) : Nil
        case wire_type
        when 0 then varint
        when 1 then advance(8)
        when 2 then bytes_field
        when 5 then advance(4)
        else        raise ArgumentError.new("unsupported protobuf wire type #{wire_type}")
        end
      end

      private def advance(count : Int32) : Nil
        raise ArgumentError.new("protobuf field exceeds input") if @offset + count > @data.size
        @offset += count
      end

      private def varint : UInt64
        result = 0_u64
        shift = 0
        loop do
          raise ArgumentError.new("malformed protobuf varint") if @offset >= @data.size || shift > 63
          byte = @data[@offset]
          @offset += 1
          raise ArgumentError.new("malformed protobuf varint") if shift == 63 && byte > 1
          result |= ((byte & 0x7f).to_u64 << shift)
          return result if byte & 0x80 == 0
          shift += 7
        end
      end
    end
  end
end

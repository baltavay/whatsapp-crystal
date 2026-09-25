require "http/web_socket"
require "uri"

module WhatsApp
  module Transport
    # WhatsApp puts a three-byte, big-endian length in front of every Noise
    # frame. The WA connection header is sent once, before the first frame.
    class FrameSocket
      URL               = "wss://web.whatsapp.com/ws/chat"
      ORIGIN            = "https://web.whatsapp.com"
      HEADER            = Bytes['W'.ord.to_u8, 'A'.ord.to_u8, 6_u8, 3_u8]
      FRAME_LENGTH_SIZE = 3
      MAX_FRAME_SIZE    = 1 << 24

      getter websocket : HTTP::WebSocket

      def initialize(@url : String = URL)
        headers = HTTP::Headers{
          "Origin"        => ORIGIN,
          "Cache-Control" => "no-cache",
          "Pragma"        => "no-cache",
        }
        @websocket = HTTP::WebSocket.new(URI.parse(@url), headers)
        @header_sent = false
        @incoming_header_checked = false
        @pending = [] of Bytes
        @incoming = Bytes.new(0)
        @expected_length = nil.as(Int32?)
      end

      # Decode one frame-length header. Keeping this separate makes malformed
      # headers fail before any slicing or allocation is attempted.
      def self.parse_frame_length(header : Bytes) : Int32
        raise ArgumentError.new("WhatsApp frame header must be exactly 3 bytes") unless header.size == FRAME_LENGTH_SIZE
        length = (header[0].to_i << 16) | (header[1].to_i << 8) | header[2].to_i
        raise ArgumentError.new("WhatsApp frame is too large") if length >= MAX_FRAME_SIZE
        length
      end

      # Wire bytes for a single frame: the optional connection header, a
      # three-byte big-endian length and the payload.
      def self.encode_frame(payload : Bytes, header : Bytes = Bytes.new(0)) : Bytes
        raise ArgumentError.new("WhatsApp frame is too large") if payload.size >= MAX_FRAME_SIZE
        frame = Bytes.new(header.size + FRAME_LENGTH_SIZE + payload.size)
        frame[0, header.size].copy_from(header) unless header.empty?
        frame[header.size] = ((payload.size >> 16) & 0xff).to_u8
        frame[header.size + 1] = ((payload.size >> 8) & 0xff).to_u8
        frame[header.size + 2] = (payload.size & 0xff).to_u8
        frame[header.size + FRAME_LENGTH_SIZE, payload.size].copy_from(payload) unless payload.empty?
        frame
      end

      def send_frame(payload : Bytes) : Nil
        @websocket.send(self.class.encode_frame(payload, @header_sent ? Bytes.new(0) : HEADER))
        @header_sent = true
      end

      def receive_frame : Bytes?
        loop do
          return @pending.shift? unless @pending.empty?
          message = @websocket.receive?
          return nil unless message
          case message
          when Bytes
            process_data(message)
          when String
            raise Error.new("unexpected text websocket message")
          else
            raise Error.new("unsupported websocket message type")
          end
        end
      end

      def close : Nil
        @websocket.close
      end

      private def process_data(data : Bytes) : Nil
        @incoming = @incoming + data
        strip_protocol_header
        loop do
          if @expected_length.nil?
            return if @incoming.size < FRAME_LENGTH_SIZE
            @expected_length = self.class.parse_frame_length(@incoming[0, FRAME_LENGTH_SIZE])
            consume(FRAME_LENGTH_SIZE)
          end

          length = @expected_length.not_nil!
          return if @incoming.size < length
          @pending << (@incoming[0, length].dup)
          consume(length)
          @expected_length = nil
        end
      end

      # Some websocket implementations echo the four-byte WA header in the
      # first server message while others do not. Accepting it explicitly is
      # safe; all subsequent data is always interpreted as frame records.
      private def strip_protocol_header : Nil
        return if @incoming_header_checked
        if @incoming.size < HEADER.size
          if @incoming.size > 0 && HEADER[0, @incoming.size] == @incoming
            return
          end
          @incoming_header_checked = true
          return
        end
        if @incoming[0, HEADER.size] == HEADER
          consume(HEADER.size)
        end
        @incoming_header_checked = true
      end

      private def consume(size : Int32) : Nil
        return if size == 0
        remaining = @incoming.size - size
        if remaining > 0
          @incoming = @incoming[size, remaining]
        else
          @incoming = Bytes.new(0)
        end
      end
    end
  end
end

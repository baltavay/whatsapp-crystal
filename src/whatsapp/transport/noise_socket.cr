require "./frame_socket"
require "../crypto/aead"

module WhatsApp
  module Transport
    class NoiseSocket
      def initialize(@frames : FrameSocket, write_key : Bytes, read_key : Bytes)
        @write_key = write_key
        @read_key = read_key
        @write_counter = 0_u32
        @read_counter = 0_u32
      end

      def send(payload : Bytes) : Nil
        encrypted = AESGCM.encrypt(@write_key, nonce(@write_counter), payload)
        @write_counter += 1
        @frames.send_frame(encrypted)
      end

      def receive : Bytes?
        encrypted = @frames.receive_frame
        return nil unless encrypted
        plaintext = AESGCM.decrypt(@read_key, nonce(@read_counter), encrypted)
        @read_counter += 1
        plaintext
      end

      def close : Nil
        @frames.close
      end

      private def nonce(counter : UInt32) : Bytes
        value = Bytes.new(12)
        value[8] = (counter >> 24).to_u8
        value[9] = (counter >> 16).to_u8
        value[10] = (counter >> 8).to_u8
        value[11] = counter.to_u8
        value
      end
    end
  end
end

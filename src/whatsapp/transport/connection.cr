require "../binary/node"
require "../pairing"

module WhatsApp
  module Native
    # Errors returned by the facade are typed so offline callers do not have
    # to parse exception text. The underlying exception is retained as cause.
    class Error < Exception
      getter kind : Symbol

      def initialize(@kind : Symbol, message : String, @cause : Exception? = nil)
        super(message, @cause)
      end
    end

    # The socket seam: a real Noise websocket in production, a recording stub in
    # tests. The client payload is built by the caller so this stays a pure
    # frame pipe.
    abstract class Connection
      abstract def connect(device : DeviceState, client_payload : Bytes) : Nil
      abstract def send(node : Binary::Node) : Nil

      # Blocks for the next node, or gives up after timeout (nil when the
      # socket is closed). Timeouts are handled by the consumer so the socket
      # is only ever read by its own reader fiber.
      abstract def receive(timeout : Time::Span? = nil) : Binary::Node?

      abstract def request(node : Binary::Node) : Binary::Node?
      abstract def close : Nil
    end
  end
end

require "./connection"

module WhatsApp
  module Native
    # Wraps a transport so protocol noise never reaches the request/response
    # callers: keepalive pings are answered, and request() waits for an actual
    # reply instead of returning the next unrelated notification. Notifications
    # stay visible to receive() so the pairing/login state machines can react to
    # them.
    class FilteredConnection < Connection
      REQUEST_TIMEOUT = 60.seconds
      REPLY_TAGS      = {"ack", "receipt", "xmlstreamend"}

      # WHATSAPP_REQUEST_TIMEOUT shortens the wait when debugging live.
      def initialize(@inner : Connection, timeout : Time::Span? = nil,
                     @on_inbound : (Binary::Node -> Nil)? = nil)
        @timeout = timeout || (ENV["WHATSAPP_REQUEST_TIMEOUT"]?.try(&.to_i.seconds) || REQUEST_TIMEOUT)
      end

      def connect(device : DeviceState, client_payload : Bytes) : Nil
        @inner.connect(device, client_payload)
      end

      def send(node : Binary::Node) : Nil
        @inner.send(node)
      end

      # Returns the next node that is not a keepalive, answering pings and
      # acknowledging inbound messages on the way. Unacked messages make the
      # server replay its whole offline queue on every connection.
      def receive(timeout : Time::Span? = nil) : Binary::Node?
        deadline = timeout.try { |window| Time.utc + window }
        loop do
          remaining = deadline.try { |value| value - Time.utc }
          return nil if remaining.try(&.<(Time::Span.zero))
          node = @inner.receive(remaining)
          return nil unless node
          next if answer_keepalive(node)
          acknowledge(node)
          if @on_inbound && {"message", "notification"}.includes?(node.tag)
            @on_inbound.not_nil!.call(node)
          end
          return node
        end
      end

      # Sends a node and reads until a reply-shaped node arrives, so callers do
      # not mistake a receipt or notification for their answer.
      def request(node : Binary::Node) : Binary::Node?
        @inner.send(node)
        request_id = node.attribute("id")
        loop do
          received = receive(@timeout) || return nil
          unless reply?(received)
            STDERR.puts "skipped while awaiting reply: #{render(received)}" if ENV["WHATSAPP_DEBUG"]?
            next
          end

          response_id = received.attribute("id")
          next if request_id && response_id && response_id != request_id
          return received
        end
      end

      def close : Nil
        @inner.close
      end

      # Compact rendering, including one level of children, so initial-bootstrap
      # nodes are diagnosable from a log line.
      private def render(node : Binary::Node) : String
        attributes = node.attrs.map { |key, value| "#{key}=#{value}" }.join(" ")
        head = attributes.empty? ? node.tag : "#{node.tag}[#{attributes}]"
        return head if node.children.empty?
        "#{head}<#{node.children.map { |child| render(child) }.join(" ")}>"
      end

      private def reply?(node : Binary::Node) : Bool
        type = node.attribute("type") || ""
        return true if node.tag == "iq" && (type == "result" || type == "error")
        return true if node.tag == "failure"
        return true if REPLY_TAGS.includes?(node.tag)
        node.tag.ends_with?(":error")
      end

      # Mirrors whatsmeow's sendAck (receipt.go): class/id plus the routing
      # attributes the server expects echoed back.
      private def acknowledge(node : Binary::Node) : Nil
        return unless node.tag == "message"
        id = node.attribute("id")
        return unless id
        attributes = Binary::Attrs{"class" => "message", "id" => id}
        {"to", "participant", "recipient"}.each do |name|
          value = name == "to" ? node.attribute("from") : node.attribute(name)
          attributes[name] = value if value && !value.empty?
        end
        @inner.send(Binary::Node.new("ack", attributes))
      end

      private def answer_keepalive(node : Binary::Node) : Bool
        return false unless node.tag == "iq" && node.attribute("xmlns") == "urn:xmpp:ping"
        attributes = Binary::Attrs{
          "to"   => node.attribute("from") || "s.whatsapp.net",
          "type" => "result",
        }
        request_id = node.attribute("id")
        attributes["id"] = request_id if request_id && !request_id.empty?
        @inner.send(Binary::Node.new("iq", attributes))
        true
      end
    end
  end
end

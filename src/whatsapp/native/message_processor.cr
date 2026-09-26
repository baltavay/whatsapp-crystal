require "../jid"

module WhatsApp
  module Native
    # Processes inbound traffic the way official clients do (whatsmeow
    # notification.go / message.go): acknowledge notifications, decrypt
    # pairwise peer messages and answer the receipts the phone waits for
    # while its linking screen shows the companion as "logging in". Without
    # these receipts the phone never finishes the initial sync and the server
    # removes the companion device about a minute after linking.
    class MessageProcessor
      # waE2E.Message field numbers: protocolMessage = 12, and inside
      # ProtocolMessage historySyncNotification = 6.
      PROTOCOL_MESSAGE_FIELD   = 12
      HISTORY_SYNC_FIELD       = 6

      def initialize(@device : DeviceState, @crypto : SignalPairwiseCrypto, @connection : Connection)
      end

      def handle(node : Binary::Node) : Nil
        case node.tag
        when "notification" then acknowledge_notification(node)
        when "message"      then handle_message(node)
        end
      rescue ex : Exception
        # Inbound processing must never break the connection: worst case a
        # receipt is missing and the phone retries the message.
        STDERR.puts "message processor dropped #{node.tag}: #{ex.class}: #{ex.message}" if ENV["WHATSAPP_DEBUG"]?
      end

      # whatsmeow notification.go sendAck: class = node tag, the sender's
      # attributes echoed back.
      private def acknowledge_notification(node : Binary::Node) : Nil
        id = node.attribute("id")
        return unless id && !id.empty?
        attributes = Binary::Attrs{"class" => node.tag, "id" => id}
        attributes["to"] = node.attribute("from") || "s.whatsapp.net"
        if type = node.attribute("type")
          attributes["type"] = type
        end
        @connection.send(Binary::Node.new("ack", attributes))
      end

      # whatsmeow message.go handleEncryptedMessage + handleProtocolMessage:
      # decrypt, then receipt the message (sender/peer_msg) and, when the
      # plaintext is a protocol message from our own account, the
      # corresponding protocol receipts (peer_msg, hist_sync).
      private def handle_message(node : Binary::Node) : Nil
        id = node.attribute("id")
        from = node.attribute("from")
        return unless id && !id.empty? && from
        enc = node.children.find { |child| child.tag == "enc" }.try(&.content)
        return unless enc

        plaintext = @crypto.decrypt(from, enc)
        protocol = ProtoScan.field_bytes(plaintext, PROTOCOL_MESSAGE_FIELD)
        history = protocol.try { |bytes| ProtoScan.field_bytes(bytes, HISTORY_SYNC_FIELD) }
        return unless own_account?(from)

        send_message_receipt(node, id, from)
        if protocol && node.attribute("category") == "peer"
          send_protocol_receipt(id, "peer_msg")
        end
        send_protocol_receipt(id, "hist_sync") if history
      end

      # whatsmeow receipt.go sendMessageReceipt: own-account messages get a
      # sender receipt directed at the message source (peer_msg type only for
      # peer_msg-typed stanzas).
      private def send_message_receipt(node : Binary::Node, id : String, from : String) : Nil
        attributes = Binary::Attrs{"id" => id, "to" => from}
        {"recipient", "participant"}.each do |name|
          value = node.attribute(name)
          attributes[name] = value if value && !value.empty?
        end
        attributes["type"] = node.attribute("type") == "peer_msg" ? "peer_msg" : "sender"
        @connection.send(Binary::Node.new("receipt", attributes))
      end

      # whatsmeow SendProtocolMessageReceipt: protocol-message receipts are
      # addressed to our own phone number with the device suffix stripped.
      private def send_protocol_receipt(id : String, type : String) : Nil
        target = own_phone_number || return
        @connection.send(Binary::Node.new("receipt", {"id" => id, "type" => type, "to" => target}))
      end

      private def own_phone_number : String?
        jid = @device.jid || return nil
        "#{JID.parse_full(jid).user}@s.whatsapp.net"
      end

      private def own_account?(from : String) : Bool
        user = JID.parse_full(from).user
        own_phone = @device.jid.try { |jid| JID.parse_full(jid).user }
        own_lid = @device.lid.try { |lid| JID.parse_full(lid).user }
        user == own_phone || user == own_lid
      end
    end

    # Minimal protobuf scanner: length-delimited field lookup, which is all
    # the receipt decisions need.
    module ProtoScan
      extend self

      def field_bytes(data : Bytes, field : Int32) : Bytes?
        offset = 0
        size = data.size
        while offset < size
          tag, offset = varint(data, offset)
          return nil if tag == 0
          case tag & 7
          when 0 then _, offset = varint(data, offset)
          when 1 then offset += 8
          when 2
            length, offset = varint(data, offset)
            return nil if offset + length > size
            return data[offset, length] if (tag >> 3) == field
            offset += length
          when 5 then offset += 4
          else        return nil
          end
        end
        nil
      end

      private def varint(data : Bytes, offset : Int32) : Tuple(UInt64, Int32)
        value = 0_u64
        shift = 0
        while offset < data.size
          byte = data[offset]
          offset += 1
          value |= (byte.to_u64 & 0x7f) << shift
          return {value, offset} if byte < 0x80
          shift += 7
          return {0_u64, offset} if shift > 63
        end
        {0_u64, offset}
      end
    end
  end
end

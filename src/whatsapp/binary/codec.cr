require "./tokens"

module WhatsApp
  module Binary
    class Codec
      LIST_EMPTY      =   0_u8
      DICTIONARY0     = 236_u8
      DICTIONARY_LAST = 239_u8
      INTEROP_JID     = 245_u8
      FBJID           = 246_u8
      ADJID           = 247_u8
      LIST8           = 248_u8
      LIST16          = 249_u8
      JID_PAIR        = 250_u8
      HEX8            = 251_u8
      BINARY8         = 252_u8
      BINARY20        = 253_u8
      BINARY32        = 254_u8
      NIBBLE8         = 255_u8
      MAX_BINARY_SIZE = 1 << 24
      PACKED_MAX      = 127

      # JID servers used by the AD/FB/Interop JID encodings.
      DEFAULT_USER_SERVER = "s.whatsapp.net"
      HIDDEN_USER_SERVER  = "lid"
      HOSTED_SERVER       = "hosted"
      HOSTED_LID_SERVER   = "hosted.lid"
      MESSENGER_SERVER    = "msgr"
      INTEROP_SERVER      = "interop"

      WHATSAPP_DOMAIN   =   0_u8
      LID_DOMAIN        =   1_u8
      HOSTED_DOMAIN     = 128_u8
      HOSTED_LID_DOMAIN = 129_u8

      SINGLE_TOKENS = Tokens::SINGLE
      DOUBLE_TOKENS = Tokens::DOUBLE

      def self.encode(node : Node) : Bytes
        io = IO::Memory.new
        write_node(io, node)
        io.to_slice
      end

      def self.decode(data : Bytes) : Node
        reader = Reader.new(data)
        reader.read_node
      end

      private def self.write_node(io : IO, node : Node) : Nil
        if node.tag == "0"
          io.write_byte(LIST8)
          io.write_byte(LIST_EMPTY)
          return
        end
        has_content = !node.content.nil? || !node.children.empty?
        size = 1 + node.attrs.size * 2 + (has_content ? 1 : 0)
        write_list_start(io, size)
        write_string(io, node.tag)
        node.attrs.each do |key, value|
          write_string(io, key)
          write_string(io, value)
        end
        if node.content
          write_bytes(io, node.content.not_nil!)
        elsif !node.children.empty?
          write_list_start(io, node.children.size)
          node.children.each { |child| write_node(io, child) }
        end
      end

      private def self.write_list_start(io : IO, size : Int32) : Nil
        if size == 0
          io.write_byte(LIST_EMPTY)
        elsif size < 256
          io.write_byte(LIST8)
          io.write_byte(size.to_u8)
        else
          # Crystal raises on narrowing without a mask, so lists longer than 255
          # children (812 prekeys in the upload IQ) must be masked explicitly.
          io.write_byte(LIST16)
          io.write_byte(((size >> 8) & 0xff).to_u8)
          io.write_byte((size & 0xff).to_u8)
        end
      end

      private def self.write_string(io : IO, value : String) : Nil
        parts = value.split('@', 2)
        if parts.size == 2 && !parts[0].empty? && !parts[1].empty?
          write_jid(io, parts[0], parts[1])
        elsif index = SINGLE_TOKENS.index(value)
          io.write_byte(index.to_u8)
        elsif token = double_token(value)
          io.write_byte((DICTIONARY0 + token[0]).to_u8)
          io.write_byte(token[1].to_u8)
        elsif nibble_packable?(value)
          # Numeric strings (JID users, phone numbers) are nibble-packed; the
          # server silently ignores requests that send them as plain binary.
          write_packed(io, value, NIBBLE8)
        elsif hex_packable?(value)
          write_packed(io, value, HEX8)
        else
          write_bytes(io, value.to_slice)
        end
      end

      # Mirrors whatsmeow's writeJID: device JIDs on the LID/default user server
      # and every hosted JID travel as AD JIDs (247 + agent + device + user),
      # not as a literal "user:device@server" pair. The server silently ignores
      # requests that encode them the literal way.
      private def self.write_jid(io : IO, user_part : String, server : String) : Nil
        parts = user_part.split(':', 2)
        user = parts[0]
        device = parts[1]?.try(&.to_u32?)

        if device && device > 0 && (server == DEFAULT_USER_SERVER || server == HIDDEN_USER_SERVER)
          io.write_byte(ADJID)
          io.write_byte(agent_for(server))
          io.write_byte((device & 0xff).to_u8)
          write_string(io, user)
        elsif server == HOSTED_SERVER || server == HOSTED_LID_SERVER
          io.write_byte(ADJID)
          io.write_byte(agent_for(server))
          io.write_byte(((device || 0) & 0xff).to_u8)
          write_string(io, user)
        elsif server == MESSENGER_SERVER
          io.write_byte(FBJID)
          write_string(io, user)
          io.write_byte((((device || 0) >> 8) & 0xff).to_u8)
          io.write_byte(((device || 0) & 0xff).to_u8)
          write_string(io, server)
        else
          io.write_byte(JID_PAIR)
          write_string(io, user)
          write_string(io, server)
        end
      end

      private def self.agent_for(server : String) : UInt8
        case server
        when HIDDEN_USER_SERVER then LID_DOMAIN
        when HOSTED_SERVER      then HOSTED_DOMAIN
        when HOSTED_LID_SERVER  then HOSTED_LID_DOMAIN
        else                         WHATSAPP_DOMAIN
        end
      end

      private def self.nibble_packable?(value : String) : Bool
        return false if value.size > PACKED_MAX
        value.each_char.all? { |char| char >= '0' && char <= '9' || char == '-' || char == '.' }
      end

      private def self.hex_packable?(value : String) : Bool
        return false if value.size > PACKED_MAX
        value.each_char.all? { |char| char >= '0' && char <= '9' || char >= 'A' && char <= 'F' }
      end

      private def self.write_packed(io : IO, value : String, tag : UInt8) : Nil
        io.write_byte(tag)
        length = (value.size + 1) // 2
        length |= 0x80 if value.size.odd?
        io.write_byte(length.to_u8)
        characters = value.chars
        index = 0
        while index < characters.size
          high = pack_char(tag, characters[index])
          low = index + 1 < characters.size ? pack_char(tag, characters[index + 1]) : 0_u8
          io.write_byte((high << 4 | low).to_u8)
          index += 2
        end
      end

      private def self.pack_char(tag : UInt8, char : Char) : UInt8
        if tag == NIBBLE8
          case char
          when '0'..'9' then (char.ord - '0'.ord).to_u8
          when '-'      then 10_u8
          when '.'      then 11_u8
          else               15_u8
          end
        else
          char <= '9' ? (char.ord - '0'.ord).to_u8 : (char.ord - 'A'.ord + 10).to_u8
        end
      end

      private def self.double_token(value : String) : Tuple(Int32, Int32)?
        DOUBLE_TOKENS.each_with_index do |dictionary, dictionary_index|
          if index = dictionary.index(value)
            return {dictionary_index, index}
          end
        end
        nil
      end

      private def self.write_bytes(io : IO, value : Bytes) : Nil
        if value.size < 256
          io.write_byte(BINARY8)
          io.write_byte(value.size.to_u8)
        elsif value.size < (1 << 20)
          io.write_byte(BINARY20)
          io.write_byte(((value.size >> 16) & 0x0f).to_u8)
          io.write_byte(((value.size >> 8) & 0xff).to_u8)
          io.write_byte((value.size & 0xff).to_u8)
        elsif value.size < MAX_BINARY_SIZE
          io.write_byte(BINARY32)
          io.write_byte(((value.size >> 24) & 0xff).to_u8)
          io.write_byte(((value.size >> 16) & 0xff).to_u8)
          io.write_byte(((value.size >> 8) & 0xff).to_u8)
          io.write_byte((value.size & 0xff).to_u8)
        else
          raise ArgumentError.new("binary node value is too large")
        end
        io.write(value)
      end

      # Wire values are strings, byte strings, JIDs or child node lists. Only
      # the first two map onto Node's fields; JIDs are rendered in WhatsApp's
      # textual form so callers do not have to carry a JID type around.
      alias Value = String | Bytes | Array(Node) | Nil

      class Reader
        def initialize(@data : Bytes)
          @offset = 0
        end

        def read_node : Node
          list_size = read_list_size(byte)
          raw_tag = read(true)
          raise Error.new("invalid WhatsApp node") unless raw_tag.is_a?(String)
          tag = raw_tag
          raise Error.new("invalid WhatsApp node") if list_size == 0 || tag.empty?

          attributes = Attrs.new
          ((list_size - 1) >> 1).times do
            key = read_string
            attributes[key] = string_value(read(true))
          end

          content = nil.as(Bytes?)
          children = [] of Node
          if list_size.even?
            case value = read(false)
            when Array(Node)
              children = value
            when String
              content = value.to_slice
            when Bytes
              content = value
            end
          end
          Node.new(tag, attributes, content, children)
        end

        private def byte : Int32
          raise Error.new("unexpected end of binary node") if @offset >= @data.size
          value = @data[@offset].to_i
          @offset += 1
          value
        end

        private def read_list_size(tag : Int32) : Int32
          case tag
          when LIST_EMPTY then 0
          when LIST8      then byte
          when LIST16     then (byte << 8) | byte
          else                 raise Error.new("invalid WhatsApp node list token: #{tag}")
          end
        end

        # Mirrors WhatsApp's binary XML value reader; as_string selects between
        # raw bytes and text for binary tokens.
        private def read(as_string : Bool) : Value
          tag = byte
          case tag
          when LIST_EMPTY
            nil
          when LIST8, LIST16
            Array(Node).new(read_list_size(tag)) { read_node }
          when BINARY8, BINARY20, BINARY32
            data = read_binary(tag)
            as_string ? String.new(data) : data
          when DICTIONARY0.to_i..DICTIONARY_LAST.to_i
            dictionary = DOUBLE_TOKENS[tag - DICTIONARY0]?
            raise Error.new("unknown WhatsApp double-byte dictionary") unless dictionary
            index = byte
            dictionary[index]? || raise Error.new("unknown WhatsApp double-byte token")
          when FBJID
            user = string_value(read(true))
            device = read_int16
            server = string_value(read(true))
            raise Error.new("unexpected Facebook JID server") unless server == MESSENGER_SERVER
            "#{user}:#{device}@#{server}"
          when INTEROP_JID
            user = string_value(read(true))
            device = read_int16
            integrator = read_int16
            server = string_value(read(true))
            raise Error.new("unexpected interop JID server") unless server == INTEROP_SERVER
            suffix = integrator == 0 ? "" : ":#{integrator}"
            "#{user}:#{device}#{suffix}@#{server}"
          when ADJID
            agent = byte
            device = byte
            user = string_value(read(true))
            format_ad_jid(user, agent.to_u8, device.to_u8)
          when JID_PAIR
            user = string_value(read(true))
            server = string_value(read(true))
            user.empty? ? server : "#{user}@#{server}"
          when HEX8, NIBBLE8
            read_packed8(tag)
          else
            if tag >= 1 && tag < SINGLE_TOKENS.size
              SINGLE_TOKENS[tag]
            else
              raise Error.new("unsupported WhatsApp string token: #{tag}")
            end
          end
        end

        private def read_string : String
          string_value(read(true))
        end

        private def string_value(value : Value) : String
          case value
          when String then value
          when Bytes  then String.new(value)
          else             ""
          end
        end

        private def read_int16 : Int32
          (byte << 8) | byte
        end

        # Nibble/hex packed strings carry phone numbers and JID users.
        private def read_packed8(tag : Int32) : String
          start = byte
          io = IO::Memory.new
          (start & 0x7f).times do
            current = byte
            io.write_byte(unpack_byte(tag, (current & 0xf0) >> 4))
            io.write_byte(unpack_byte(tag, current & 0x0f))
          end
          value = io.to_s
          (start & 0x80) != 0 && !value.empty? ? value[0, value.size - 1] : value
        end

        private def unpack_byte(tag : Int32, value : Int32) : UInt8
          if tag == NIBBLE8
            case value
            when 0..9 then ('0'.ord + value).to_u8
            when 10   then '-'.ord.to_u8
            when 11   then '.'.ord.to_u8
            when 15   then 0_u8
            else           raise Error.new("invalid nibble packed string value: #{value}")
            end
          else
            case value
            when 0..9   then ('0'.ord + value).to_u8
            when 10..15 then ('A'.ord + value - 10).to_u8
            else             raise Error.new("invalid hex packed string value: #{value}")
            end
          end
        end

        # AD JIDs encode their domain type in the agent byte, exactly like
        # whatsmeow's types.NewADJID, and render as user.agent:device@server.
        private def format_ad_jid(user : String, agent : UInt8, device : UInt8) : String
          server = DEFAULT_USER_SERVER
          raw_agent = agent
          case agent
          when LID_DOMAIN
            server = HIDDEN_USER_SERVER
            raw_agent = 0_u8
          when HOSTED_DOMAIN
            server = HOSTED_SERVER
            raw_agent = 0_u8
          when HOSTED_LID_DOMAIN
            server = HOSTED_LID_SERVER
            raw_agent = 0_u8
          end
          if raw_agent > 0
            "#{user}.#{raw_agent}:#{device}@#{server}"
          elsif device > 0
            "#{user}:#{device}@#{server}"
          elsif !user.empty?
            "#{user}@#{server}"
          else
            server
          end
        end

        private def read_binary(token : Int32) : Bytes
          length = case token
                   when BINARY8  then byte
                   when BINARY20 then (byte.to_i64 << 16 | byte.to_i64 << 8 | byte).to_i
                   when BINARY32 then (byte.to_i64 << 24 | byte.to_i64 << 16 | byte.to_i64 << 8 | byte).to_i
                   else               raise Error.new("invalid binary token")
                   end
          raise Error.new("binary node exceeds input") if @offset + length > @data.size
          value = @data[@offset, length].dup
          @offset += length
          value
        end
      end
    end
  end
end

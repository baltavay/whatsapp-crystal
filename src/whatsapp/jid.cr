module WhatsApp
  struct JID
    getter user : String
    getter server : String
    getter device : UInt32

    def initialize(@user : String, @server : String, @device : UInt32 = 0_u32)
    end

    def group? : Bool
      @server == "g.us" && !@user.empty?
    end

    def to_s(io : IO) : Nil
      io << @user
      io << ':' << @device if @device > 0
      io << '@' << @server
    end

    def user_int : UInt64
      @user.to_u64
    end

    def self.parse(value : String) : JID
      user, server = value.split('@', 2)
      raise ArgumentError.new("invalid JID: #{value}") unless user && server && !user.empty? && !server.empty?
      jid = new(user, server)
      raise ArgumentError.new("expected a WhatsApp group JID ending in @g.us") unless jid.group?
      jid
    end

    # Companion JIDs carry a device suffix (user:device@server). Unlike parse,
    # this accepts any server because login payloads need the account JID.
    def self.parse_full(value : String) : JID
      user, server = value.split('@', 2)
      raise ArgumentError.new("invalid JID: #{value}") unless user && server && !user.empty? && !server.empty?
      parts = user.split(':', 2)
      user_part = parts[0]
      device_part = parts[1]?
      raise ArgumentError.new("invalid JID: #{value}") if user_part.empty?
      begin
        new(user_part, server, device_part ? device_part.to_u32 : 0_u32)
      rescue ArgumentError
        raise ArgumentError.new("invalid JID device: #{value}")
      end
    end
  end
end

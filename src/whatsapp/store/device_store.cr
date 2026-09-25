require "../pairing"
require "./session"

module WhatsApp
  module Store
    # Owns the SQLite session and the serialised linked-device identity.
    #
    # The store intentionally exposes DeviceState rather than JSON so callers
    # cannot accidentally persist a partially populated identity.
    class DeviceStore
      getter session : Session
      getter owns_session : Bool

      def initialize(path : String)
        @session = Session.new(path)
        @owns_session = true
      end

      def initialize(@session : Session)
        @owns_session = false
      end

      def path : String
        @session.path
      end

      def load_or_create : DeviceState
        DeviceState.load_or_create(@session)
      end

      def save(device : DeviceState) : Nil
        device.save(@session)
      end

      def close : Nil
        @session.close if @owns_session
      end
    end
  end
end

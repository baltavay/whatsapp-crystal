require "digest/md5"
require "./client_payload"
require "./companion"
require "./writer"
require "../pairing"
require "../store/prekeys"

module WhatsApp
  module Proto
    # Companion client payloads, ported from whatsmeow's store/clientpayload.go.
    # The registration payload is what the server needs before it will offer
    # <pair-device>; the login payload is what a paired companion sends instead.
    module Registration
      # WhatsApp Web version the companion claims to be.
      WA_VERSION       = "2.3000.1047769893"
      WA_VERSION_PARTS = {2_u64, 3000_u64, 1047769893_u64}

      WEB_PLATFORM                  = 14_u64
      RELEASE_CHANNEL_RELEASE       =  0_u64
      CONNECT_TYPE_WIFI_UNKNOWN     =  1_u64
      CONNECT_REASON_USER_ACTIVATED =  1_u64

      # Label the phone shows for this companion under Linked devices. whatsmeow
      # uses Os: "whatsmeow" in store.DeviceProps; it is only sent at pairing.
      DEFAULT_DEVICE_NAME = "whatsapp-crystal"

      def self.version_hash : Bytes
        Digest::MD5.digest(WA_VERSION)
      end

      def self.registration_payload(device : DeviceState, device_name : String = DEFAULT_DEVICE_NAME) : Bytes
        payload = base
        payload.passive = false
        payload.pull = false
        payload.session_id = 0

        registration = ClientPayload::DevicePairingRegistrationData.new
        registration.registration_id = big_endian32(device.registration_id)
        registration.key_type = Bytes[PreKey::DJB_TYPE]
        registration.identity = device.identity_key.public_key
        registration.signed_key_id = device.signed_prekey.wire_id
        registration.signed_key = device.signed_prekey.public_key
        registration.signed_key_signature = device.signed_prekey.signature
        registration.build_hash = version_hash
        registration.device_props = Companion::DeviceProps.web(device_name).encode
        payload.pairing_data = registration
        payload.encode
      end

      def self.login_payload(device : DeviceState) : Bytes
        account = device.jid || raise Error.new("cannot build a login payload for an unpaired device")
        jid = JID.parse_full(account)

        payload = base
        payload.username = jid.user_int
        payload.device = jid.device.to_u64
        payload.passive = true
        payload.pull = true
        payload.lc = 1
        payload.lid_db_migrated = true
        payload.encode
      end

      def self.base : ClientPayload
        payload = ClientPayload.new

        agent = ClientPayload::UserAgent.new
        agent.platform = WEB_PLATFORM
        version = ClientPayload::AppVersion.new
        version.primary = WA_VERSION_PARTS[0]
        version.secondary = WA_VERSION_PARTS[1]
        version.tertiary = WA_VERSION_PARTS[2]
        agent.app_version = version
        agent.mcc = "000"
        agent.mnc = "000"
        agent.os_version = "0.1"
        agent.manufacturer = ""
        agent.device = "Desktop"
        agent.os_build_number = "0.1"
        agent.release_channel = RELEASE_CHANNEL_RELEASE
        agent.locale_language = "en"
        agent.locale_country = "US"
        payload.user_agent = agent

        web_info = ClientPayload::WebInfo.new
        web_info.subplatform = 0_u64 # WEB_BROWSER
        web_info.payload = ClientPayload::WebdPayload.new
        payload.web_info = web_info

        payload.connect_type = CONNECT_TYPE_WIFI_UNKNOWN
        payload.connect_reason = CONNECT_REASON_USER_ACTIVATED
        payload
      end

      private def self.big_endian32(value : UInt32) : Bytes
        bytes = Bytes.new(4)
        IO::ByteFormat::BigEndian.encode(value, bytes)
        bytes
      end
    end
  end
end

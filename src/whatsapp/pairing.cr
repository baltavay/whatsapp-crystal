require "base64"
require "json"
require "random/secure"
require "./crypto/curve25519"
require "./proto/adv"
require "./store/prekeys"
require "./store/session"

module WhatsApp
  # A QR reference is short-lived. Keeping its lifecycle explicit prevents a
  # caller from treating a stale generated code as a completed pairing.
  enum PairingPhase
    QRReady
    Scanned
    Completed
    Expired
  end

  class PairingState
    QR_TTL_SECONDS = 160

    getter reference : Bytes
    getter client_type : String
    getter qr : String
    getter created_at : Time
    getter phase : PairingPhase

    def initialize(device : DeviceState, reference : Bytes, @client_type : String = "Chrome", @created_at : Time = Time.utc)
      raise ArgumentError.new("pairing reference must not be empty") if reference.empty?
      raise ArgumentError.new("pairing client type must not be empty") if @client_type.empty? || @client_type.includes?(',')
      @reference = reference.dup
      @qr = build_qr(device)
      @phase = PairingPhase::QRReady
    end

    def expired?(now : Time = Time.utc) : Bool
      @phase == PairingPhase::Expired || now >= @created_at + Time::Span.new(seconds: QR_TTL_SECONDS)
    end

    def mark_scanned! : Nil
      raise Error.new("pairing QR has expired") if expired?
      raise Error.new("pairing QR is no longer ready") unless @phase == PairingPhase::QRReady
      @phase = PairingPhase::Scanned
    end

    def mark_completed! : Nil
      raise Error.new("pairing QR has expired") if expired?
      raise Error.new("pairing QR was not scanned") unless @phase == PairingPhase::Scanned
      @phase = PairingPhase::Completed
    end

    def expire! : Nil
      @phase = PairingPhase::Expired
    end

    private def build_qr(device : DeviceState) : String
      # The server reference is already the printable QR token; unlike the
      # device keys it must not be base64-encoded a second time.
      [
        "https://wa.me/settings/linked_devices#",
        String.new(@reference), ',',
        Base64.strict_encode(device.noise_key.public_key), ',',
        Base64.strict_encode(device.identity_key.public_key), ',',
        Base64.strict_encode(device.adv_secret), ',',
        @client_type,
      ].join
    end
  end

  # Everything the linked-device identity consists of: the long-term keys, the
  # prekey material the server hands out on our behalf, and — once paired — the
  # ADV account identity the primary device signed for us.
  class DeviceState
    SIGNED_PREKEY_ID      = 1_u32
    PREKEY_BATCH          =    50
    INITIAL_PREKEY_COUNT  =   812
    SERVER_PREKEY_MINIMUM =     5
    DEFAULT_PUSH_NAME     = "Crystal"

    getter noise_key : Crypto::Curve25519KeyPair
    getter identity_key : Crypto::Curve25519KeyPair
    getter adv_secret : Bytes
    getter jid : String?
    getter registration_id : UInt32
    getter lid : String?
    getter business_name : String?
    getter platform : String?
    getter signed_prekey : PreKey
    getter one_time_prekeys : Array(PreKey)
    getter next_prekey_id : UInt32
    getter account : Proto::ADV::SignedDeviceIdentity?
    getter prekey_uploaded_id : UInt32
    # Sent as <presence name=.../> after login; without it the server has no
    # pushname for this companion (whatsmeow store.Device.PushName).
    getter push_name : String

    def initialize(
      @noise_key,
      @identity_key,
      @adv_secret,
      @jid = nil,
      registration_id : UInt32? = nil,
      @lid = nil,
      @business_name = nil,
      @platform = nil,
      signed_prekey : PreKey? = nil,
      @one_time_prekeys = [] of PreKey,
      next_prekey_id : UInt32? = nil,
      @account : Proto::ADV::SignedDeviceIdentity? = nil,
      @prekey_uploaded_id = 0_u32,
      @push_name = DEFAULT_PUSH_NAME,
    )
      @registration_id = registration_id || self.class.random_registration_id
      @signed_prekey = signed_prekey || PreKey.generate_signed(SIGNED_PREKEY_ID, @identity_key)
      @next_prekey_id = next_prekey_id || (@one_time_prekeys.max_of?(&.id) || 0_u32) + 1
    end

    def self.load_or_create(session : Store::Session) : self
      if state = session.read
        device = decode_state(state)
        device.try { |loaded| return loaded }
      end

      state = new(Crypto::Curve25519KeyPair.generate, Crypto::Curve25519KeyPair.generate, Random::Secure.random_bytes(32))
      state.save(session)
      state
    end

    def paired? : Bool
      !@jid.nil? && !@account.nil?
    end

    # Marks the device as paired with the identity the primary device signed.
    def complete_pairing(jid : String, lid : String?, business_name : String?, platform : String?, account : Proto::ADV::SignedDeviceIdentity) : Nil
      @jid = jid
      @lid = lid
      @business_name = business_name
      @platform = platform
      @account = account
    end

    def save(session : Store::Session) : Nil
      payload = JSON.build do |json|
        json.object do
          json.field "noise_private", Base64.strict_encode(@noise_key.private_key)
          json.field "noise_public", Base64.strict_encode(@noise_key.public_key)
          json.field "identity_private", Base64.strict_encode(@identity_key.private_key)
          json.field "identity_public", Base64.strict_encode(@identity_key.public_key)
          json.field "adv_secret", Base64.strict_encode(@adv_secret)
          json.field "jid", @jid
          json.field "lid", @lid
          json.field "business_name", @business_name
          json.field "platform", @platform
          json.field "registration_id", @registration_id.to_s
          json.field "signed_prekey", @signed_prekey.to_json_value
          json.field "next_prekey_id", @next_prekey_id.to_s
          json.field "prekey_uploaded_id", @prekey_uploaded_id.to_s
          json.field "push_name", @push_name
          json.field "account" do
            if account = @account
              json.object do
                json.field "details", Base64.strict_encode(account.details)
                json.field "account_signature_key", account.account_signature_key.try { |value| Base64.strict_encode(value) }
                json.field "account_signature", account.account_signature.try { |value| Base64.strict_encode(value) }
                json.field "device_signature", account.device_signature.try { |value| Base64.strict_encode(value) }
              end
            else
              json.null
            end
          end
          json.field "one_time_prekeys" do
            json.array do
              @one_time_prekeys.each { |prekey| json.raw prekey.to_json_value.to_json }
            end
          end
        end
      end
      session.write(payload)
    end

    # Generates and appends one-time prekeys, returning the new ones so the
    # caller can upload exactly what is missing on the server.
    def generate_prekeys(count : Int32) : Array(PreKey)
      generated = [] of PreKey
      count.times do
        prekey = PreKey.generate(@next_prekey_id)
        @next_prekey_id += 1
        @one_time_prekeys << prekey
        generated << prekey
      end
      generated
    end

    def unuploaded_prekeys : Array(PreKey)
      @one_time_prekeys.select { |prekey| prekey.id > @prekey_uploaded_id }
    end

    def mark_prekeys_uploaded(through_id : UInt32) : Nil
      @prekey_uploaded_id = through_id if through_id > @prekey_uploaded_id
    end

    def self.random_registration_id : UInt32
      bytes = Random::Secure.random_bytes(4)
      ((bytes[0].to_u64 << 24) | (bytes[1].to_u64 << 16) | (bytes[2].to_u64 << 8) | bytes[3].to_u64).to_u32
    end

    # JSON::Any#[]? refuses to index a null value, so absent fields and fields
    # written as null both have to be normalized to nil before nested access.
    private def self.field(state : JSON::Any, name : String) : JSON::Any?
      value = state[name]?
      return nil unless value
      value.raw.nil? ? nil : value
    end

    private def self.decode_state(state : JSON::Any) : self?
      noise_private = decode(field(state, "noise_private"))
      noise_public = decode(field(state, "noise_public"))
      identity_private = decode(field(state, "identity_private"))
      identity_public = decode(field(state, "identity_public"))
      adv_secret = decode(field(state, "adv_secret"))
      return nil unless noise_private && noise_public && identity_private && identity_public && adv_secret

      identity_key = Crypto::Curve25519KeyPair.new(identity_private, identity_public)
      prekeys = (field(state, "one_time_prekeys").try(&.as_a?) || [] of JSON::Any).compact_map { |entry| PreKey.from_json_value(entry) }
      new(
        Crypto::Curve25519KeyPair.new(noise_private, noise_public),
        identity_key,
        adv_secret,
        jid: field(state, "jid").try(&.as_s?),
        registration_id: parse_u32(field(state, "registration_id")),
        lid: field(state, "lid").try(&.as_s?),
        business_name: field(state, "business_name").try(&.as_s?),
        platform: field(state, "platform").try(&.as_s?),
        signed_prekey: field(state, "signed_prekey").try { |value| PreKey.from_json_value(value) } || PreKey.generate_signed(SIGNED_PREKEY_ID, identity_key),
        one_time_prekeys: prekeys,
        next_prekey_id: parse_u32(field(state, "next_prekey_id")),
        account: decode_account(field(state, "account")),
        push_name: field(state, "push_name").try(&.as_s?) || DEFAULT_PUSH_NAME,
        prekey_uploaded_id: parse_u32(field(state, "prekey_uploaded_id")) || 0_u32,
      )
    end

    private def self.decode_account(value : JSON::Any?) : Proto::ADV::SignedDeviceIdentity?
      return nil unless value
      details = decode(value["details"]?)
      return nil unless details
      Proto::ADV::SignedDeviceIdentity.new(
        details: details,
        account_signature_key: decode(value["account_signature_key"]?),
        account_signature: decode(value["account_signature"]?),
        device_signature: decode(value["device_signature"]?),
      )
    end

    private def self.parse_u32(value : JSON::Any?) : UInt32?
      value.try { |raw| raw.as_s.to_u32 }
    rescue
      nil
    end

    private def self.decode(value : JSON::Any?) : Bytes?
      value.try { |raw| Base64.decode(raw.as_s) }
    rescue
      nil
    end

    def pairing_state(reference : Bytes, client_type : String = "Chrome") : PairingState
      PairingState.new(self, reference, client_type)
    end

    def qr_data(reference : Bytes, client_type : String = "Chrome") : String
      pairing_state(reference, client_type).qr
    end
  end
end

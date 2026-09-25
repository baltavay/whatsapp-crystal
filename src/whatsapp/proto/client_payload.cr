require "random/secure"
require "digest/sha256"
require "base64"
require "json"
require "./writer"
require "../crypto/curve25519"
require "../store/session"

module WhatsApp
  module Proto
    # Minimal WA6 client-payload encoder for a web companion. Field numbers and
    # nested message layout mirror WAWebProtobufsWa6.proto.
    class ClientPayload
      property username : UInt64?
      property passive : Bool?
      property push_name : String?
      property session_id : Int32?
      property short_connect : Bool?
      property lc : Int32?
      property pull : Bool?
      property lid_db_migrated : Bool?
      property connect_type : UInt64?
      property connect_reason : UInt64?
      property device : UInt64?
      property product : UInt64?
      property account_type : UInt64?
      property user_agent : UserAgent?
      property web_info : WebInfo?
      property pairing_data : DevicePairingRegistrationData?

      def initialize
      end

      def encode : Bytes
        writer = Writer.new
        writer.uint(1, @username.not_nil!) if @username
        writer.bool(3, @passive.not_nil!) if @passive
        writer.message(5, @user_agent.not_nil!.encode) if @user_agent
        writer.message(6, @web_info.not_nil!.encode) if @web_info
        writer.string(7, @push_name.not_nil!) if @push_name
        writer.fixed32(9, @session_id.not_nil!.to_u32) if @session_id
        writer.bool(10, @short_connect.not_nil!) if @short_connect
        writer.uint(12, @connect_type.not_nil!) if @connect_type
        writer.uint(13, @connect_reason.not_nil!) if @connect_reason
        writer.uint(18, @device.not_nil!) if @device
        writer.message(19, @pairing_data.not_nil!.encode) if @pairing_data
        writer.uint(20, @product.not_nil!) if @product
        writer.uint(24, @lc.not_nil!.to_u32.to_u64) if @lc
        writer.bool(33, @pull.not_nil!) if @pull
        writer.bool(41, @lid_db_migrated.not_nil!) if @lid_db_migrated
        writer.uint(42, @account_type.not_nil!) if @account_type
        writer.bytes
      end

      class UserAgent
        property platform : UInt64?
        property app_version : AppVersion?
        property mcc : String?
        property mnc : String?
        property os_version : String?
        property manufacturer : String?
        property device : String?
        property os_build_number : String?
        property release_channel : UInt64?
        property locale_language : String?
        property locale_country : String?
        property device_type : UInt64?

        def encode : Bytes
          writer = Writer.new
          writer.uint(1, @platform.not_nil!) if @platform
          writer.message(2, @app_version.not_nil!.encode) if @app_version
          writer.string(3, @mcc.not_nil!) if @mcc
          writer.string(4, @mnc.not_nil!) if @mnc
          writer.string(5, @os_version.not_nil!) if @os_version
          writer.string(6, @manufacturer.not_nil!) if @manufacturer
          writer.string(7, @device.not_nil!) if @device
          writer.string(8, @os_build_number.not_nil!) if @os_build_number
          writer.uint(10, @release_channel.not_nil!) if @release_channel
          writer.string(11, @locale_language.not_nil!) if @locale_language
          writer.string(12, @locale_country.not_nil!) if @locale_country
          writer.uint(15, @device_type.not_nil!) if @device_type
          writer.bytes
        end
      end

      class AppVersion
        property primary : UInt64?
        property secondary : UInt64?
        property tertiary : UInt64?

        def encode : Bytes
          writer = Writer.new
          writer.uint(1, @primary.not_nil!) if @primary
          writer.uint(2, @secondary.not_nil!) if @secondary
          writer.uint(3, @tertiary.not_nil!) if @tertiary
          writer.bytes
        end
      end

      class WebInfo
        property ref_token : String?
        property version : String?
        property subplatform : UInt64?
        property browser : String?
        property browser_version : String?
        property payload : WebdPayload?

        def encode : Bytes
          writer = Writer.new
          writer.string(1, @ref_token.not_nil!) if @ref_token
          writer.string(2, @version.not_nil!) if @version
          writer.message(3, @payload.not_nil!.encode) if @payload
          writer.uint(4, @subplatform.not_nil!) if @subplatform
          writer.string(5, @browser.not_nil!) if @browser
          writer.string(6, @browser_version.not_nil!) if @browser_version
          writer.bytes
        end
      end

      class WebdPayload
        property supports_document_messages : Bool = true
        property supports_url_messages : Bool = true
        property supports_media_retry : Bool = true
        property supports_e2e_image : Bool = true
        property supports_e2e_document : Bool = true
        property document_types : String = "application/pdf,image/jpeg,image/png"

        def encode : Bytes
          writer = Writer.new
          writer.bool(3, @supports_document_messages)
          writer.bool(4, @supports_url_messages)
          writer.bool(5, @supports_media_retry)
          writer.bool(6, @supports_e2e_image)
          writer.bool(9, @supports_e2e_document)
          writer.string(10, @document_types)
          writer.bytes
        end
      end

      class DevicePairingRegistrationData
        property registration_id : Bytes?
        property key_type : Bytes?
        property identity : Bytes?
        property signed_key_id : Bytes?
        property signed_key : Bytes?
        property signed_key_signature : Bytes?
        property build_hash : Bytes?
        property device_props : Bytes?

        def encode : Bytes
          writer = Writer.new
          writer.raw(1, @registration_id.not_nil!) if @registration_id
          writer.raw(2, @key_type.not_nil!) if @key_type
          writer.raw(3, @identity.not_nil!) if @identity
          writer.raw(4, @signed_key_id.not_nil!) if @signed_key_id
          writer.raw(5, @signed_key.not_nil!) if @signed_key
          writer.raw(6, @signed_key_signature.not_nil!) if @signed_key_signature
          writer.raw(7, @build_hash.not_nil!) if @build_hash
          writer.raw(8, @device_props.not_nil!) if @device_props
          writer.bytes
        end
      end
    end
  end
end

require "./whatsapp/jid"
require "./whatsapp/binary/node"
require "./whatsapp/binary/codec"
require "./whatsapp/binary/frame"
require "./whatsapp/crypto/hkdf"
require "./whatsapp/crypto/media"
require "./whatsapp/crypto/curve25519"
require "./whatsapp/crypto/xeddsa"
require "./whatsapp/crypto/certificate"
require "./whatsapp/crypto/aead"
require "./whatsapp/crypto/noise"
require "./whatsapp/transport/frame_socket"
require "./whatsapp/transport/noise_socket"
require "./whatsapp/proto/messages"
require "./whatsapp/proto/writer"
require "./whatsapp/store/prekeys"
require "./whatsapp/pairing"
require "./whatsapp/transport/handshake"
require "./whatsapp/proto/handshake"
require "./whatsapp/crypto/group/sender_key"
require "./whatsapp/crypto/group/sender_key_distribution_message"
require "./whatsapp/crypto/group/sender_key_message"
require "./whatsapp/crypto/group/group_cipher"
require "./whatsapp/crypto/group/in_memory_store"
require "./whatsapp/proto/adv"
require "./whatsapp/proto/companion"
require "./whatsapp/proto/pairing"
require "./whatsapp/proto/client_payload"
require "./whatsapp/media"
require "./whatsapp/store/session"
require "./whatsapp/store/device_store"
require "./whatsapp/native_client"
require "json"

module WhatsApp
  VERSION = "0.1.0"

  class Error < Exception
  end

  struct Config
    getter group_jid : String?
    getter session_db : String
    getter websocket_url : String
    getter media_host : String?
    getter media_auth : String?

    def initialize(
      @group_jid : String? = ENV["WHATSAPP_GROUP_JID"]?,
      @session_db : String = ENV.fetch("WHATSAPP_SESSION_DB", "./whatsapp-session.db"),
      @websocket_url : String = ENV.fetch("WHATSAPP_WS_URL", Transport::FrameSocket::URL),
      @media_host : String? = ENV["WHATSAPP_MEDIA_HOST"]?,
      @media_auth : String? = ENV["WHATSAPP_MEDIA_AUTH"]?,
    )
    end
  end

  class Client
    def initialize(@config : Config = Config.new)
      connection = Native::WebSocketConnection.new(@config.websocket_url)
      media = if host = @config.media_host
                auth = @config.media_auth || raise Error.new("WHATSAPP_MEDIA_AUTH is required with WHATSAPP_MEDIA_HOST")
                Native::MediaUploaderTransport.new(MediaConnection.new(host, auth))
              end
      @native = Native::Client.new(@config.session_db, connection, media)
    end

    # Sends text to the configured (or given) group and returns the message id.
    def send_text(text : String, group : String? = nil) : String
      target = ensure_group!(group)
      result = @native.send_text(target, text)
      raise_native!(result.error)
      result.id.not_nil!
    end

    # Uploads a file as a WhatsApp document and returns the message id.
    def send_file(path : String, caption : String = "", mime : String? = nil, group : String? = nil) : String
      target = ensure_group!(group)
      result = @native.send_document(target, path, caption, mime)
      raise_native!(result.error)
      result.id.not_nil!
    end

    # Uploads an image and returns the message id.
    def send_photo(path : String, caption : String = "", mime : String? = nil, group : String? = nil) : String
      target = ensure_group!(group)
      result = @native.send_photo(target, path, caption, mime)
      raise_native!(result.error)
      result.id.not_nil!
    end

    # Joined groups as (jid, name) pairs.
    def groups : Array(Native::Group)
      login
      result = @native.groups
      raise_native!(result.error)
      result.groups
    end

    # Runs the QR pairing handshake and returns the payload the phone scans.
    def pair : String
      connect!
      result = @native.pair
      raise_native!(result.error)
      qr = result.qr || raise Error.new("the server did not send a pairing reference")
      qr
    end

    # Blocks until the phone scans the QR, then reports the paired device JID.
    # The server refreshes the QR references while waiting; every new payload is
    # handed to the block so the caller can re-render it.
    def await_pair_success(&qr_handler : String ->) : String
      result = @native.await_pair_success(&qr_handler)
      raise_native!(result.error)
      unless result.paired?
        raise Error.new("pairing did not complete")
      end
      result.device.try(&.jid) || ""
    end

    # Links this companion and immediately logs in, so a single command leaves a
    # usable session: after <pair-success> WhatsApp drops the socket, and a paired
    # device logs in with a different client payload.
    def pair_and_login(&qr_handler : String ->) : String
      qr = pair
      qr_handler.call(qr)
      jid = await_pair_success(&qr_handler)
      close
      login
      jid
    end

    # Unlinks this companion device from the account and returns its JID.
    def logout : String?
      login
      result = @native.logout
      raise_native!(result.error)
      result.device.try(&.jid)
    end

    # Handshake plus login for an already paired companion.
    def login : Nil
      connect!
      return if @native.logged_in?
      result = @native.login
      raise_native!(result.error)
    end

    def close : Nil
      @native.close
    end

    private def connect! : Nil
      return if @native.connected?
      result = @native.connect
      raise_native!(result.error)
    end

    private def ensure_group!(override : String?) : String
      jid = override || @config.group_jid
      unless jid
        raise Error.new("a group JID is required: pass group: or set WHATSAPP_GROUP_JID")
      end
      JID.parse(jid)
      login
      jid
    rescue ex : ArgumentError
      raise Error.new(ex.message || "invalid WhatsApp group JID")
    end

    private def raise_native!(native_error : Native::Error?) : Nil
      return unless native_error
      raise Error.new(native_error.message || native_error.kind.to_s)
    end
  end
end

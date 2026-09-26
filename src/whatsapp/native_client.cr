require "base64"
require "digest/sha256"
require "openssl/hmac"
require "random/secure"
require "./jid"
require "./crypto/aead"
require "./crypto/hkdf"
require "./crypto/noise"
require "./crypto/xeddsa"
require "./pairing"
require "./binary/frame"
require "./binary/node"
require "./binary/codec"
require "./proto/adv"
require "./proto/messages"
require "./proto/pairing"
require "./proto/registration"
require "./transport/frame_socket"

module WhatsApp
  module Transport
    alias AESGCM = WhatsApp::Crypto::AESGCM
  end
end

require "./transport/connection"
require "./transport/filtered_connection"
require "./transport/handshake"
require "./transport/noise_socket"
require "./media"
require "./store/device_store"
require "./store/prekeys"
require "./crypto_bridge"
require "./native/message_processor"

module WhatsApp
  module Native
    struct ConnectResult
      getter device : DeviceState?
      getter error : Error?

      def initialize(@device : DeviceState?, @error : Error?)
      end

      def success? : Bool
        !@device.nil? && @error.nil?
      end
    end

    struct PairResult
      getter qr : String?
      getter refs : Array(String)
      getter device : DeviceState?
      getter error : Error?

      def initialize(@qr : String?, @device : DeviceState?, @error : Error?, @refs = [] of String)
      end

      def success? : Bool
        @error.nil? && !@qr.nil?
      end

      def paired? : Bool
        @error.nil? && @device.try(&.paired?) == true
      end
    end

    struct SendResult
      getter id : String?
      getter error : Error?

      def initialize(@id : String?, @error : Error?)
      end

      def success? : Bool
        !@id.nil? && @error.nil?
      end
    end

    struct Group
      getter jid : String
      getter name : String

      def initialize(@jid : String, @name : String = "")
      end
    end

    struct GroupListResult
      getter groups : Array(Group)
      getter error : Error?

      def initialize(@groups : Array(Group), @error : Error?)
      end

      def success? : Bool
        @error.nil?
      end
    end

    # Real websocket implementation. It is the only default implementation
    # that touches FrameSocket, HandshakeClient, and NoiseSocket.
    class WebSocketConnection < Connection
      getter url : String

      def initialize(@url : String = Transport::FrameSocket::URL)
        @frames = nil.as(Transport::FrameSocket?)
        @noise = nil.as(Transport::NoiseSocket?)
        @incoming = nil.as(Channel(Binary::Node?)?)
        @read_error = nil.as(Exception?)
      end

      def connect(device : DeviceState, client_payload : Bytes) : Nil
        frames = Transport::FrameSocket.new(@url)
        handshake = Transport::HandshakeClient.new(device, ->(certificate : Bytes, static : Bytes) { Crypto::NoiseCertificate.verify(certificate, static) })
        handshake.send_client_hello(frames)
        handshake.receive_server_hello(frames)
        handshake.send_client_finish(frames, client_payload)
        keys = handshake.noise.transport_keys
        @frames = frames
        socket = Transport::NoiseSocket.new(frames, keys[0], keys[1])
        @noise = socket
        start_reader(socket)
      end

      # A single fiber owns reading the socket; consumers wait on its channel
      # with their own deadline, so a timeout never leaves a read in flight.
      private def start_reader(socket : Transport::NoiseSocket) : Nil
        channel = Channel(Binary::Node?).new(64)
        @incoming = channel
        @read_error = nil
        spawn do
          loop do
            # NoiseSocket owns frame reading and decryption, so the socket is
            # only ever touched by this fiber.
            payload = socket.receive
            unless payload
              STDERR.puts "reader: socket closed by the server" if ENV["WHATSAPP_DEBUG"]?
              break
            end
            body = Binary::Frame.unpack(payload)
            if path = ENV["WHATSAPP_DEBUG_RAW"]?
              File.open(path, "a") { |file| file.puts body.map { |byte| byte.to_s(16).rjust(2, '0') }.join }
            end
            channel.send(Binary::Codec.decode(body))
          end
          channel.send(nil)
        rescue ex
          # Surface the failure to the consumer instead of looking like a timeout.
          @read_error = ex
          STDERR.puts "reader error: #{ex.class}: #{ex.message}" if ENV["WHATSAPP_DEBUG"]?
          channel.send(nil)
        end
      end

      def send(node : Binary::Node) : Nil
        ensure_noise!.send(Binary::Frame.pack(Binary::Codec.encode(node)))
      end

      def receive(timeout : Time::Span? = nil) : Binary::Node?
        channel = @incoming || raise Error.new(:not_connected, "WhatsApp transport is not connected")
        node = if timeout
                 select
                 when received = channel.receive
                   received
                 when timeout(timeout)
                   nil
                 end
               else
                 channel.receive
               end
        raise @read_error.not_nil! if node.nil? && @read_error
        node
      end

      def request(node : Binary::Node) : Binary::Node?
        send(node)
        receive
      end

      def close : Nil
        if socket = @noise
          socket.close
        elsif frames = @frames
          frames.close
        end
        @noise = nil
        @frames = nil
      end

      private def ensure_noise! : Transport::NoiseSocket
        @noise || raise Error.new(:not_connected, "WhatsApp transport is not connected")
      end
    end

    abstract class MediaTransport
      abstract def upload(path : String, kind : Symbol, mime_type : String?) : UploadResponse
    end

    # Adapter around the existing encrypted-media uploader. Tests can provide
    # a MediaTransport that records uploads without making an HTTP request.
    class MediaUploaderTransport < MediaTransport
      def initialize(@connection : MediaConnection)
      end

      def upload(path : String, kind : Symbol, mime_type : String?) : UploadResponse
        MediaUploader.new(@connection).upload(path, kind, mime_type)
      end
    end

    # Native client facade. It owns the persisted companion identity, drives the
    # pairing/login state machine and delegates every socket operation to an
    # injectable Connection.
    class Client
      ACCOUNT_SIGNATURE_PREFIX = Bytes[0x06_u8, 0x00_u8]
      DEVICE_SIGNATURE_PREFIX  = Bytes[0x06_u8, 0x01_u8]
      HOSTED_ACCOUNT_PREFIX    = Bytes[0x06_u8, 0x05_u8]
      HOSTED_ACCOUNT_TYPE      = 1_u32

      CONNECT_TIMEOUT          = 2.minutes

      # Compliant QR client-type suffix (whatsmeow pair.go getQRClientType,
      # issue #1110): a single-character platform code, not a name. We present
      # as a generic web browser — DeviceProps platform UNKNOWN with the
      # WEB_BROWSER subplatform maps to PairClientOtherWebClient ("9").
      QR_CLIENT_TYPE = "9"

      getter store : Store::DeviceStore
      getter connection : Connection
      getter media : MediaTransport?
      getter device : DeviceState?
      getter qr : String?
      getter sender : Sender?

      def initialize(
        @store : Store::DeviceStore,
        @connection : Connection = WebSocketConnection.new,
        @media : MediaTransport? = nil,
        @group_crypto : GroupCrypto? = nil,
        @pairwise : PairwiseCrypto? = nil,
        @device_name : String = Proto::Registration::DEFAULT_DEVICE_NAME,
      )
        @device = nil.as(DeviceState?)
        @connected = false
        @logged_in = false
        @qr = nil.as(String?)
        @sender = nil.as(Sender?)
        @signal_store = nil.as(Crypto::Signal::Store::SQLite?)
        @seen = [] of String
        # Server clock skew in seconds (t attr of pair-success/success); the
        # unified session id must be computed in server time.
        @server_time_offset = 0_i64
        # Keepalive answering and reply matching belong to the transport layer;
        # inbound messages and notifications go through the message processor.
        @message_processor = nil.as(MessageProcessor?)
        @connection = FilteredConnection.new(connection, on_inbound: ->inbound(Binary::Node))
      end

      def initialize(
        path : String,
        connection : Connection = WebSocketConnection.new,
        media : MediaTransport? = nil,
        group_crypto : GroupCrypto? = nil,
        pairwise : PairwiseCrypto? = nil,
        device_name : String = Proto::Registration::DEFAULT_DEVICE_NAME,
      )
        initialize(Store::DeviceStore.new(path), connection, media, group_crypto, pairwise, device_name)
      end

      def connected? : Bool
        @connected
      end

      def logged_in? : Bool
        @logged_in
      end

      # Loads (or creates) the companion identity, completes the Noise handshake
      # with the registration payload (unpaired) or login payload (paired).
      def connect : ConnectResult
        state = @store.load_or_create
        payload = state.paired? ? Proto::Registration.login_payload(state) : Proto::Registration.registration_payload(state, @device_name)
        @connection.connect(state, payload)
        @device = state
        @connected = true
        ConnectResult.new(state, nil)
      rescue ex : Exception
        @connected = false
        ConnectResult.new(nil, wrap_error(:connect, ex))
      end

      # Waits for the server's <pair-device> IQ, acknowledges it and returns the
      # QR payloads the phone must scan.
      def pair(timeout : Time::Span = CONNECT_TIMEOUT) : PairResult
        state = @store.load_or_create
        @device = state
        node = next_node(timeout) || return pair_failure("timed out waiting for the pairing request")
        unless node.tag == "iq" && node.child("pair-device")
          return pair_failure("expected a pair-device IQ, got <#{node.tag}>")
        end
        acknowledge(node)
        refs = Proto::Pairing::DeviceRefs.parse(node)
        return pair_failure("pairing request carried no reference") if refs.empty?
        @qr = state.qr_data(refs.first.to_slice, client_type)
        PairResult.new(@qr, state, nil, refs)
      rescue ex : Exception
        PairResult.new(nil, nil, wrap_error(:pair, ex))
      end

      def await_pair_success(timeout : Time::Span = CONNECT_TIMEOUT) : PairResult
        await_pair_success(timeout) { |_qr| }
      end

      # After the phone scans the QR the server sends <pair-success>; verify the
      # ADV identity, sign it with our identity key, confirm and persist. The
      # server rotates the QR references while it waits, so a repeated
      # <pair-device> is acknowledged and its fresh QR handed to the caller.
      def await_pair_success(timeout : Time::Span = CONNECT_TIMEOUT, &qr_handler : String ->) : PairResult
        state = @device || @store.load_or_create
        loop do
          node = next_node(timeout) || return pair_failure("timed out waiting for pair-success#{recent_nodes}", state)
          if node.tag == "iq" && node.child("pair-device")
            acknowledge(node)
            refs = Proto::Pairing::DeviceRefs.parse(node)
            unless refs.empty?
              @qr = state.qr_data(refs.first.to_slice, client_type)
              qr_handler.call(@qr.not_nil!)
            end
            next
          end

          success = begin
            Proto::Pairing::Success.parse(node)
          rescue ex : WhatsApp::Error | ArgumentError
            # Unrelated traffic (receipts, notifications, pings) is not a
            # pairing failure: keep waiting for the real pair-success.
            next unless node.tag == "iq" && (node.child("pair-success") || node.tag == "pair-success")
            return pair_failure("#{ex.message} (node: #{describe(node)})", state)
          end
          remember_server_time(node)
          key_index = begin
            complete_pairing(state, success)
          rescue ex : WhatsApp::Error | ArgumentError
            return pair_failure("#{ex.message} (node: #{describe(node)})", state)
          end
          confirmation = Binary::Node.new("pair-device-sign", Binary::Attrs.new, nil, [
            Binary::Node.new("device-identity", {"key-index" => key_index.to_s}, confirmation_identity(state)),
          ])
          acknowledge(node, [confirmation])
          # Official web clients report a unified-session id right after the
          # pairing confirmation (whatsmeow handlePairSuccess does the same,
          # racing the disconnect that follows pair-device-sign).
          send_unified_session
          return PairResult.new(nil, state, nil)
        end
      rescue ex : Exception
        PairResult.new(nil, nil, located_error(:pair_success, ex))
      end

      # Paired devices log in instead of pairing: wait for <success>, store the
      # LID, publish our prekeys and leave passive mode.
      # Asking the server for a fresh connection straight after another one can
      # be dropped (it allows a single companion connection); retry once after a
      # short pause instead of failing the whole command.
      def login(timeout : Time::Span = CONNECT_TIMEOUT) : ConnectResult
        # whatsmeow ErrNotLoggedIn: without a paired device the login sequence
        # can only produce a confusing server stream error.
        state = @device || @store.load_or_create
        return ConnectResult.new(nil, error(:not_logged_in, "this device is not linked; run pair first")) unless state.jid
        result = perform_login(timeout)
        return result unless transport_failure?(result)
        sleep 3.seconds
        reconnect = connect
        return result if reconnect.error
        perform_login(timeout)
      end

      private def transport_failure?(result : ConnectResult) : Bool
        cause = result.error.try(&.cause)
        cause.is_a?(IO::Error)
      end

      private def perform_login(timeout : Time::Span = CONNECT_TIMEOUT) : ConnectResult
        state = @device || @store.load_or_create
        return ConnectResult.new(nil, error(:not_connected, "call connect before login")) unless @connected
        dirty = [] of Tuple(String, String)
        collections = [] of Tuple(String, String)
        loop do
          node = next_node(timeout) || return ConnectResult.new(nil, error(:login, "timed out waiting for login success#{recent_nodes}"))
          if node.tag == "success"
            remember_server_time(node)
            apply_success(state, node)
            break
          elsif node.tag == "ib" || node.tag == "notification"
            collect_dirty(node, dirty)
            collect_collections(node, collections)
          elsif node.tag == "failure"
            return ConnectResult.new(nil, failure_error(node))
          elsif node.tag == "stream:error"
            return ConnectResult.new(nil, error(:login, "stream error during login: #{node.attrs.inspect}"))
          end
        end
        # The server announces pending collections after <success>, so give them
        # a moment to arrive before syncing.
        drain_bootstrap(dirty, collections)
        mark_clean(dirty)
        sync_app_state(collections)
        server_prekey_count
        upload_prekeys(state)
        set_passive(false)
        # Real clients announce presence right after login: it publishes the
        # pushname and takes the companion out of WhatsApp's "logging in" state.
        send_presence(state)
        # Presence-available is when official clients report the unified-session
        # id (whatsmeow SendPresence does this); a companion that never sends
        # it is fingerprinted as unofficial and removed shortly after linking.
        send_unified_session
        # Official clients end the login bootstrap by syncing every standard
        # app-state collection, not just the ones announced in <ib>.
        sync_remaining_app_state(dirty, collections)
        @logged_in = true
        ConnectResult.new(state, nil)
      rescue ex : Exception
        ConnectResult.new(nil, wrap_error(:login, ex))
      end

      # Joined groups via the group server (whatsmeow group.go GetJoinedGroups).
      def groups : GroupListResult
        ensure_logged_in!

        request = Binary::Node.new("iq", attrs(type: "get", xmlns: "w:g2", to: "g.us", id: message_id), nil, [
          Binary::Node.new("participating", nil, nil, [
            Binary::Node.new("participants"),
            Binary::Node.new("description"),
          ]),
        ])
        response = @connection.request(request)
        STDERR.puts "groups response: #{response ? describe(response) : "none"}" if ENV["WHATSAPP_DEBUG"]?
        GroupListResult.new(parse_groups(response), nil)
      rescue ex : Exception
        GroupListResult.new([] of Group, wrap_error(:groups, ex))
      end

      def group_list : GroupListResult
        groups
      end

      # Client-side keepalive (whatsmeow keepalive.go): the companion must
      # ping the server while idle. A socket that is only read when a caller
      # waits for a reply goes silent for the server, is dropped after about
      # a minute, and the phone-side linking then never completes. The ping
      # round trip also drains queued server pings and runs inbound messages
      # through the processor (FilteredConnection). False means "reconnect".
      # w:p is the query official clients use for keepalive.
      def ping : Bool
        return false unless @connected && @logged_in
        request = Binary::Node.new("iq", attrs(type: "get", xmlns: "w:p", to: "s.whatsapp.net", id: message_id))
        response = @connection.request(request)
        !response.nil? && response.tag == "iq" && response.attribute("type") == "result"
      rescue ex : Exception
        false
      end

      private def inbound(node : Binary::Node) : Nil
        message_processor!.handle(node)
      end

      # The inbound processor owns the receiving Signal stack. The device's
      # prekeys live in the device store; seed them into the Signal store so
      # the first inbound prekey message can complete its X3DH handshake.
      private def message_processor! : MessageProcessor
        @message_processor ||= begin
          state = @device || @store.load_or_create
          signal_store = signal_store()
          unless signal_store.local_identity
            signal_store.save_local_identity(state.identity_key)
            signal_store.local_registration_id = state.registration_id
            signal_store.save_signed_prekey(state.signed_prekey.id, state.signed_prekey.key_pair, state.signed_prekey.signature.not_nil!)
            state.one_time_prekeys.each do |prekey|
              signal_store.save_one_time_prekey(prekey.id, prekey.key_pair)
            end
          end
          MessageProcessor.new(state, SignalPairwiseCrypto.new(signal_store, state), @connection)
        end
      end

      def send_text(group_jid : String, text : String) : SendResult
        return failure(:send_text, "text must not be empty") if text.empty?
        send_message(group_jid, "text", text_message(text))
      rescue ex : Exception
        SendResult.new(nil, wrap_error(:send_text, ex))
      end

      def send_photo(group_jid : String, path : String, caption : String = "", mime_type : String? = nil) : SendResult
        send_media(group_jid, path, :image, caption, mime_type)
      rescue ex : Exception
        SendResult.new(nil, wrap_error(:send_photo, ex))
      end

      def send_document(group_jid : String, path : String, caption : String = "", mime_type : String? = nil) : SendResult
        send_media(group_jid, path, :document, caption, mime_type)
      rescue ex : Exception
        SendResult.new(nil, wrap_error(:send_document, ex))
      end

      # Removes this companion from the account (whatsmeow client.go Logout):
      # the phone stops listing it and this session can no longer authenticate.
      def logout : ConnectResult
        state = @device || @store.load_or_create
        jid = state.jid || return ConnectResult.new(nil, error(:logout, "this device is not linked"))
        ensure_logged_in!
        request = Binary::Node.new("iq", attrs(type: "set", xmlns: "md", to: "s.whatsapp.net", id: message_id), nil, [
          Binary::Node.new("remove-companion-device", {"jid" => jid, "reason" => "user_initiated"}),
        ])
        response = @connection.request(request)
        if response && (response.tag == "error" || response.attribute("type") == "error")
          return ConnectResult.new(nil, error(:logout, "the server refused the logout: #{describe(response)}"))
        end
        close
        # Parity with whatsmeow Logout: the store is deleted, so a later run
        # starts from a clean, unlinked state instead of a 401 device_removed.
        @store.clear!
        @device = nil
        ConnectResult.new(state, nil)
      rescue ex : Exception
        ConnectResult.new(nil, wrap_error(:logout, ex))
      end

      # Low-level escape hatch for diagnostics and callers that speak IQ directly.
      def request(node : Binary::Node) : Binary::Node?
        @connection.request(node)
      end

      def send_node(node : Binary::Node) : Nil
        @connection.send(node)
      end

      def close : Nil
        @connection.close if @connected
        @connected = false
        @logged_in = false
      end

      private def send_media(group_jid : String, path : String, kind : Symbol, caption : String, mime_type : String?) : SendResult
        return failure(kind == :image ? :send_photo : :send_document, "file does not exist: #{path}") unless File.file?(path)
        uploader = @media || discover_media!
        uploaded = uploader.upload(path, kind, mime_type || (kind == :image ? "image/jpeg" : "application/octet-stream"))
        message = kind == :image ? image_message(uploaded, caption, mime_type) : document_message(uploaded, path, caption, mime_type)
        # Media messages travel as type="media" with a separate mediatype.
        send_message(group_jid, "media", message, kind.to_s)
      end

      private def send_message(group_jid : String, type : String, message : Proto::Message, media_type : String? = nil) : SendResult
        ensure_logged_in!
        state = @device || @store.load_or_create
        id = web_message_id
        group_crypto = @group_crypto || GroupSenderCrypto.new(@store.session, state)
        pairwise = @pairwise || SignalPairwiseCrypto.new(signal_store, state)
        @sender ||= Sender.new(@connection, state, group_crypto, pairwise)
        @sender.not_nil!.send_group_message(group_jid, id, type, message, media_type)
        SendResult.new(id, nil)
      end

      # Signal state shares the session database file.
      private def signal_store : Crypto::Signal::Store::SQLite
        @signal_store ||= Crypto::Signal::Store::SQLite.new(@store.path)
      end

      private def ensure_logged_in! : Nil
        raise Error.new(:not_connected, "WhatsApp client is not logged in") unless @logged_in
      end

      private def discover_media! : MediaTransport
        ensure_logged_in!
        request = Binary::Node.new("iq", attrs(id: message_id, type: "set", xmlns: "w:m", to: "s.whatsapp.net"), nil, [
          Binary::Node.new("media_conn"),
        ])
        response = @connection.request(request) || raise Error.new(:media_discovery_failed, "media connection query returned no response")
        media = response.tag == "media_conn" ? response : response.child("media_conn")
        media ||= response.children.find { |child| child.tag == "media_conn" }
        media = media || raise Error.new(:media_discovery_failed, "media connection response has no media_conn node")
        auth = media.attribute("auth") || raise Error.new(:media_discovery_failed, "media connection response has no auth")
        host_node = media.children.find { |child| child.tag == "host" }
        host = host_node.try(&.attribute("hostname")) || host_node.try(&.attribute("host"))
        host = host || raise Error.new(:media_discovery_failed, "media connection response has no host")
        @media = MediaUploaderTransport.new(MediaConnection.new(host, auth))
      end

      # --- pairing helpers -------------------------------------------------

      private def complete_pairing(state : DeviceState, success : Proto::Pairing::Success) : UInt64
        container = Proto::ADV::SignedDeviceIdentityHMAC.decode(success.device_identity)
        raise Error.new(:pairing, "pair-success device identity is missing its HMAC") if container.hmac.empty?
        prefix = container.account_type == HOSTED_ACCOUNT_TYPE ? HOSTED_ACCOUNT_PREFIX : Bytes.new(0)
        expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, state.adv_secret, prefix + container.details)
        raise Error.new(:pairing, "pair-success HMAC does not match our ADV secret") unless constant_time_equal?(expected, container.hmac)

        signed = Proto::ADV::SignedDeviceIdentity.decode(container.details)
        account_key = signed.account_signature_key || raise Error.new(:pairing, "pair-success has no account signature key")
        account_signature = signed.account_signature || raise Error.new(:pairing, "pair-success has no account signature")
        identity = state.identity_key.public_key

        account_message = ACCOUNT_SIGNATURE_PREFIX + signed.details + identity
        raise Error.new(:pairing, "pair-success account signature is invalid") unless Crypto::XEdDSA.verify(account_key, account_message, account_signature)

        device_signature = Crypto::XEdDSA.sign(state.identity_key.private_key, DEVICE_SIGNATURE_PREFIX + signed.details + identity + account_key)
        account = Proto::ADV::SignedDeviceIdentity.new(
          details: signed.details,
          account_signature_key: account_key,
          account_signature: account_signature,
          device_signature: device_signature,
        )
        jid = success.jid || raise Error.new(:pairing, "pair-success has no device JID")
        state.complete_pairing(jid, success.lid, success.business_name, success.platform, account)
        @store.save(state)
        Proto::ADV::DeviceIdentity.decode(signed.details).key_index
      end

      private def confirmation_identity(state : DeviceState) : Bytes
        account = state.account || raise Error.new(:pairing, "device has no ADV account identity")
        Proto::ADV::SignedDeviceIdentity.new(
          details: account.details,
          account_signature: account.account_signature,
          device_signature: account.device_signature,
        ).encode
      end

      # Echoes the server's IQ back as a result. The id is only included when the
      # server sent one, since an empty id cannot be matched to anything.
      private def acknowledge(node : Binary::Node, children : Array(Binary::Node) = [] of Binary::Node) : Nil
        request_id = node.attribute("id")
        attributes = Binary::Attrs{
          "to"   => node.attribute("from") || "s.whatsapp.net",
          "type" => "result",
        }
        attributes["id"] = request_id if request_id && !request_id.empty?
        @connection.send(Binary::Node.new("iq", attributes, nil, children))
      end

      # Compact node rendering used in pairing failure messages.
      private def describe(node : Binary::Node, depth : Int32 = 0) : String
        attributes = node.attrs.map { |key, value| "#{key}=#{value}" }.join(" ")
        text = String.build do |io|
          io << node.tag
          io << '[' << attributes << ']' unless attributes.empty?
          io << "(" << node.content.not_nil!.size << "B)" if node.content
        end
        return text if depth >= 2 || node.children.empty?
        "#{text}<#{node.children.map { |child| describe(child, depth + 1) }.join(" ")}>"
      end

      # <success> carries the account LID, which we persist for later addressing.
      private def apply_success(state : DeviceState, node : Binary::Node) : Nil
        lid = node.attribute("lid")
        return if lid.nil? || lid.empty?
        account = state.account
        jid = state.jid
        return unless account && jid
        state.complete_pairing(jid, lid, state.business_name, state.platform, account)
        @store.save(state)
      end

      # --- login helpers ---------------------------------------------------

      # Asks the server how many of our one-time prekeys it still holds
      # (whatsmeow prekeys.go getServerPreKeyCount). Part of the post-login
      # sequence a companion is expected to perform.
      def server_prekey_count : Int32?
        request = Binary::Node.new("iq", attrs(type: "get", xmlns: "encrypt", to: "s.whatsapp.net", id: message_id), nil, [
          Binary::Node.new("count"),
        ])
        response = @connection.request(request)
        STDERR.puts "prekey count response: #{response ? describe(response) : "none"}" if ENV["WHATSAPP_DEBUG"]?
        return nil unless response
        count = response.tag == "count" ? response : response.child("count")
        count.try(&.attribute("value")).try(&.to_i32)
      end

      private def upload_prekeys(state : DeviceState) : Nil
        wanted = state.one_time_prekeys.empty? ? DeviceState::INITIAL_PREKEY_COUNT : DeviceState::PREKEY_BATCH
        state.generate_prekeys(wanted - state.unuploaded_prekeys.size) if state.unuploaded_prekeys.size < wanted
        keys = state.unuploaded_prekeys.first(wanted)
        raise Error.new(:prekeys, "no one-time prekeys to upload") if keys.empty?

        signed = state.signed_prekey
        signature = signed.signature || raise Error.new(:prekeys, "signed prekey has no signature")
        request = Binary::Node.new("iq", attrs(type: "set", xmlns: "encrypt", to: "s.whatsapp.net", id: message_id), nil, [
          Binary::Node.new("registration", nil, big_endian32(state.registration_id)),
          Binary::Node.new("type", nil, Bytes[PreKey::DJB_TYPE]),
          Binary::Node.new("identity", nil, state.identity_key.public_key),
          Binary::Node.new("list", nil, nil, keys.map { |prekey| prekey_node("key", prekey) }),
          Binary::Node.new("skey", nil, nil, [
            Binary::Node.new("id", nil, signed.wire_id),
            Binary::Node.new("value", nil, signed.public_key),
            Binary::Node.new("signature", nil, signature),
          ]),
        ])

        response = @connection.request(request)
        STDERR.puts "prekey upload response: #{response ? describe(response) : "none"}" if ENV["WHATSAPP_DEBUG"]?
        if response && (response.tag == "error" || response.attribute("type") == "error")
          raise Error.new(:prekeys, "prekey upload was rejected: #{describe(response)}")
        end
        state.mark_prekeys_uploaded(keys.last.id)
        @store.save(state)
      end

      private def prekey_node(tag : String, prekey : PreKey) : Binary::Node
        Binary::Node.new(tag, nil, nil, [
          Binary::Node.new("id", nil, prekey.wire_id),
          Binary::Node.new("value", nil, prekey.public_key),
        ])
      end

      # The server flags app-state collections as dirty (in <ib> and in
      # account_sync/server_sync notifications); clients confirm they caught up
      # with <iq xmlns="urn:xmpp:whatsapp:dirty"><clean .../></iq>
      # (whatsmeow appstate.go MarkNotDirty).
      private def collect_dirty(node : Binary::Node, dirty : Array(Tuple(String, String))) : Nil
        children = node.tag == "ib" ? node.children : [node]
        children.each do |child|
          type = child.attribute("type")
          next unless type
          next unless {"dirty", "account_sync", "server_sync"}.includes?(child.tag) ||
                      {"account_sync", "server_sync"}.includes?(type)
          timestamp = child.attribute("timestamp") || child.attribute("t") || Time.utc.to_unix.to_s
          dirty << {type, timestamp}
        end
      end

      # server_sync notifications name app-state collections the companion is
      # behind on: <collection name="regular_low" version="36"/>.
      private def collect_collections(node : Binary::Node, collections : Array(Tuple(String, String))) : Nil
        return unless node.tag == "notification" && node.attribute("type") == "server_sync"
        node.children.each do |child|
          next unless child.tag == "collection"
          name = child.attribute("name") || next
          collections << {name, child.attribute("version") || "0"}
        end
      end

      # Bounded read so collection announcements that follow <success> are seen.
      private def drain_bootstrap(dirty : Array(Tuple(String, String)), collections : Array(Tuple(String, String)), window : Time::Span = 4.seconds) : Nil
        deadline = Time.utc + window
        while Time.utc < deadline
          node = receive_node(1.second)
          break unless node
          collect_dirty(node, dirty)
          collect_collections(node, collections)
        end
      end

      # Fetches an app-state collection (whatsmeow appstate.go
      # fetchAppStatePatches): the payload is not applied yet, only fetched and
      # marked clean so the companion stops being considered behind.
      def sync_app_state(collections : Array(Tuple(String, String))) : Nil
        collections.uniq.each do |(name, _version)|
          request = Binary::Node.new("iq", attrs(type: "set", xmlns: "w:sync:app:state", to: "s.whatsapp.net", id: message_id), nil, [
            Binary::Node.new("sync", nil, nil, [
              Binary::Node.new("collection", {"name" => name, "return_snapshot" => "true"}),
            ]),
          ])
          response = @connection.request(request)
          STDERR.puts "app state #{name}: #{response ? describe(response)[0, 240] : "none"}" if ENV["WHATSAPP_DEBUG"]?
        end
      end

      # The collections official clients sync on a fresh login (whatsmeow
      # appstate.go): anything the server did not already announce in the
      # bootstrap is fetched with return_snapshot so the companion catches up.
      APP_STATE_COLLECTIONS = ["critical_block", "critical_unblock_low", "regular_high", "regular", "regular_low"]

      private def sync_remaining_app_state(dirty : Array(Tuple(String, String)), collections : Array(Tuple(String, String))) : Nil
        pending = APP_STATE_COLLECTIONS - collections.map(&.[0])
        sync_app_state(pending.map { |name| {name, "0"} }) unless pending.empty?
      end

      # <pair-success>/<success> carry the server clock in the t attribute;
      # the unified session id must be computed in server time.
      private def remember_server_time(node : Binary::Node) : Nil
        timestamp = node.attribute("t").try(&.to_i64?)
        @server_time_offset = timestamp - Time.utc.to_unix if timestamp
      end

      # Unified-session telemetry (whatsmeow client.go sendUnifiedSession, PR
      # #1057): id = ((server_now + 3 days) mod 7 days) in milliseconds. Sent
      # after pairing and with presence-available; never fatal.
      private def send_unified_session : Nil
        window_ms = 7 * 24 * 3600 * 1000_i64
        offset_ms = 3 * 24 * 3600 * 1000_i64
        server_now_ms = Time.utc.to_unix_ms + @server_time_offset * 1000
        id = ((server_now_ms + offset_ms) % window_ms).to_s
        @connection.send(Binary::Node.new("ib", Binary::Attrs.new, nil, [
          Binary::Node.new("unified_session", {"id" => id}),
        ]))
      rescue ex : Exception
        STDERR.puts "unified_session send failed: #{ex.class}: #{ex.message}" if ENV["WHATSAPP_DEBUG"]?
      end

      private def mark_clean(dirty : Array(Tuple(String, String))) : Nil
        dirty.uniq.each do |(type, timestamp)|
          request = Binary::Node.new("iq", attrs(type: "set", xmlns: "urn:xmpp:whatsapp:dirty", to: "s.whatsapp.net", id: message_id), nil, [
            Binary::Node.new("clean", {"type" => type, "timestamp" => timestamp}),
          ])
          response = @connection.request(request)
          STDERR.puts "mark clean #{type}=#{timestamp}: #{response ? describe(response) : "none"}" if ENV["WHATSAPP_DEBUG"]?
        end
      end

      def send_presence(state : DeviceState) : Nil
        @connection.send(Binary::Node.new("presence", {"type" => "available", "name" => state.push_name}))
      end

      private def set_passive(passive : Bool) : Nil
        child = passive ? Binary::Node.new("passive") : Binary::Node.new("active")
        request = Binary::Node.new("iq", attrs(type: "set", xmlns: "passive", to: "s.whatsapp.net", id: message_id), nil, [child])
        @connection.request(request)
      end

      private def failure_error(node : Binary::Node) : Error
        reason = node.attribute("reason") || "unknown"
        message = node.attribute("message")
        detail = message ? "#{reason}: #{message}" : reason
        error(:login, "WhatsApp refused the login (#{detail})")
      end

      # --- shared helpers --------------------------------------------------

      # Returns the next node the state machine cares about, recording recent
      # traffic so failures can explain what actually arrived.
      def next_node(timeout : Time::Span?) : Binary::Node?
        node = receive_node(timeout)
        return nil unless node
        @seen << describe(node)
        @seen.shift if @seen.size > 5
        node
      end

      private def recent_nodes : String
        @seen.empty? ? "" : " (recent: #{@seen.join(" | ")})"
      end

      def receive_node(timeout : Time::Span?) : Binary::Node?
        @connection.receive(timeout)
      end

      private def parse_groups(response : Binary::Node?) : Array(Group)
        groups = [] of Group
        return groups unless response
        container = response.tag == "groups" ? response : (response.child("groups") || response)
        container.children.each do |node|
          next unless node.tag == "group"
          # The group server reports the numeric id; whatsmeow turns it into a
          # <id>@g.us JID, and there is no jid attribute on the node.
          id = node.attribute("id") || node.attribute("jid")
          next unless id
          jid = id.includes?('@') ? id : "#{id}@g.us"
          groups << Group.new(jid, node.attribute("subject") || node.attribute("name") || "")
        end
        groups
      end

      private def text_message(text : String) : Proto::Message
        message = Proto::Message.new
        message.conversation = text
        message
      end

      private def image_message(uploaded : UploadResponse, caption : String, mime_type : String?) : Proto::Message
        image = Proto::ImageMessage.new
        image.url = uploaded.url
        image.direct_path = uploaded.direct_path
        image.mimetype = mime_type || "image/jpeg"
        image.caption = caption unless caption.empty?
        image.media_key = uploaded.encrypted.media_key
        image.file_sha256 = uploaded.encrypted.file_sha256
        image.file_enc_sha256 = uploaded.encrypted.file_enc_sha256
        image.file_length = uploaded.encrypted.plaintext_length
        message = Proto::Message.new
        message.image = image
        message
      end

      private def document_message(uploaded : UploadResponse, path : String, caption : String, mime_type : String?) : Proto::Message
        document = Proto::DocumentMessage.new
        document.url = uploaded.url
        document.direct_path = uploaded.direct_path
        document.mimetype = mime_type || "application/octet-stream"
        document.title = File.basename(path)
        document.file_name = File.basename(path)
        document.caption = caption unless caption.empty?
        document.media_key = uploaded.encrypted.media_key
        document.file_sha256 = uploaded.encrypted.file_sha256
        document.file_enc_sha256 = uploaded.encrypted.file_enc_sha256
        document.file_length = uploaded.encrypted.plaintext_length
        message = Proto::Message.new
        message.document = document
        message
      end

      private def client_type : String
        QR_CLIENT_TYPE
      end

      private def pair_failure(message : String, device : DeviceState? = nil) : PairResult
        PairResult.new(nil, device, error(:pair, message))
      end

      private def failure(kind : Symbol, message : String) : SendResult
        SendResult.new(nil, error(kind, message))
      end

      private def error(kind : Symbol, message : String) : Error
        Error.new(kind, message)
      end

      # Failure messages name the origin so opaque server-side surprises can be
      # pinned down from a single log line.
      private def located_error(kind : Symbol, exception : Exception) : Error
        return exception if exception.is_a?(Error)
        frames = exception.backtrace?.try(&.first(3).join(" <- ")) || "no backtrace"
        Error.new(kind, "#{exception.class}: #{exception.message} at #{frames}", exception)
      end

      private def wrap_error(kind : Symbol, exception : Exception) : Error
        return exception if exception.is_a?(Error)
        # Keep the exception class visible: opaque messages cost debugging time
        # against a server that gives no error detail.
        Error.new(kind, "#{exception.class}: #{exception.message || "no message"}", exception)
      end

      private def message_id : String
        Base64.urlsafe_encode(Random::Secure.random_bytes(8), padding: false)
      end

      # WhatsApp Web message ids are "3EB0" plus uppercase hex of 8 random bytes
      # (whatsmeow send.go GenerateMessageID); other formats are not delivered.
      def web_message_id : String
        "3EB0" + Random::Secure.random_bytes(8).map { |byte| byte.to_s(16).rjust(2, '0') }.join.upcase
      end

      private def big_endian32(value : UInt32) : Bytes
        bytes = Bytes.new(4)
        IO::ByteFormat::BigEndian.encode(value, bytes)
        bytes
      end

      # HMAC comparison without early exit.
      private def constant_time_equal?(left : Bytes, right : Bytes) : Bool
        return false unless left.size == right.size
        difference = 0_u8
        left.each_with_index { |byte, index| difference |= (byte ^ right[index]) }
        difference == 0
      end

      private def attrs(**values : String) : Binary::Attrs
        result = Binary::Attrs.new
        values.each { |key, value| result[key.to_s] = value }
        result
      end
    end

    alias NativeClient = Client
  end

  alias NativeClient = Native::Client
end

require "../pairing"
require "../proto/handshake"
require "../crypto/noise"
require "./frame_socket"

module WhatsApp
  module Transport
    class HandshakeClient
      PATTERN = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
      alias CertificateVerifier = Proc(Bytes, Bytes, Bool)

      getter ephemeral : Crypto::Curve25519KeyPair
      getter noise : Crypto::NoiseHandshake
      getter server_ephemeral : Bytes?
      getter server_static : Bytes?
      getter server_certificate : Bytes?
      getter server_certificate_verified : Bool?

      # True only when the caller-provided verifier accepted the certificate.
      def certificate_verified? : Bool
        @server_certificate_verified == true
      end

      # A verifier receives the decrypted certificate and the authenticated
      # server static key. No verifier is supplied by default: the certificate
      # chain format is intentionally not claimed to be implemented here.
      def initialize(@device : DeviceState, @certificate_verifier : CertificateVerifier? = nil)
        @ephemeral = Crypto::Curve25519KeyPair.generate
        @noise = Crypto::NoiseHandshake.new.start(PATTERN, FrameSocket::HEADER)
        @noise.authenticate(@ephemeral.public_key)
        @client_hello_sent = false
        @server_hello_received = false
        @client_finish_sent = false
      end

      def send_client_hello(frames : FrameSocket) : Nil
        raise Error.new("client hello was already sent") if @client_hello_sent
        hello = Proto::Handshake.new(Proto::ClientHello.new(@ephemeral.public_key))
        frames.send_frame(hello.encode)
        @client_hello_sent = true
      end

      def receive_server_hello(frames : FrameSocket) : Nil
        raise Error.new("client hello has not been sent") unless @client_hello_sent
        raise Error.new("server hello was already received") if @server_hello_received
        response = frames.receive_frame || raise Error.new("websocket closed during Noise handshake")
        handshake = Proto::Handshake.decode(response)
        hello = handshake.server_hello || raise Error.new("Noise response did not contain server hello")

        @noise.authenticate(hello.ephemeral)
        @noise.mix_shared_secret(@ephemeral, hello.ephemeral)
        static = @noise.decrypt(hello.static)
        raise Error.new("invalid server static key") unless static.size == 32
        @server_ephemeral = hello.ephemeral.dup
        @server_static = static

        # Noise XX: the server's certificate payload is encrypted with the key
        # mixed from DH(client ephemeral, server static) — "es" — not from the
        # ephemeral-ephemeral secret that unlocked the static key.
        @noise.mix_shared_secret(@ephemeral, static)

        certificate = @noise.decrypt(hello.payload)
        raise Error.new("empty server certificate payload") if certificate.empty?
        @server_certificate = certificate
        if verifier = @certificate_verifier
          unless verifier.call(certificate, static)
            raise Error.new("server certificate verification failed")
          end
          @server_certificate_verified = true
        else
          @server_certificate_verified = false
        end
        @server_hello_received = true
      end

      # Sends the encrypted client static key and client payload after the
      # server hello. Certificate validation is opt-in via the verifier hook;
      # the native client must not pretend an unverified chain is trusted.
      def send_client_finish(frames : FrameSocket, client_payload : Bytes) : Nil
        raise Error.new("server hello has not been received") unless @server_hello_received
        raise Error.new("client finish was already sent") if @client_finish_sent
        raise Error.new("client payload exceeds maximum handshake size") if client_payload.size > Proto::MAX_HANDSHAKE_SIZE
        server_ephemeral = @server_ephemeral || raise Error.new("server ephemeral key is unavailable")
        encrypted_static = @noise.encrypt(@device.noise_key.public_key)
        @noise.mix_shared_secret(@device.noise_key, server_ephemeral)
        encrypted_payload = @noise.encrypt(client_payload)
        finish = Proto::Writer.new.raw(1, encrypted_static).raw(2, encrypted_payload).bytes
        message = Proto::Writer.new.raw(4, finish).bytes
        raise Error.new("client finish exceeds maximum handshake size") if message.size > Proto::MAX_HANDSHAKE_SIZE
        frames.send_frame(message)
        @client_finish_sent = true
      end
    end
  end
end

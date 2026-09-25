require "base64"
require "digest/sha256"
require "http/client"
require "json"
require "uri"
require "./crypto/media"

module WhatsApp
  struct MediaConnection
    getter host : String
    getter auth : String

    def initialize(@host : String, @auth : String)
    end
  end

  struct UploadResponse
    getter url : String
    getter direct_path : String
    getter handle : String
    getter object_id : String
    getter encrypted : Crypto::EncryptedMedia

    def initialize(@url, @direct_path, @handle, @object_id, @encrypted)
    end
  end

  class MediaUploader
    def initialize(@connection : MediaConnection)
    end

    def upload(path : String, kind : Symbol, mime_type : String? = nil) : UploadResponse
      plaintext = File.read(path).to_slice
      media_info = case kind
                   when :image    then "WhatsApp Image Keys"
                   when :document then "WhatsApp Document Keys"
                   else                raise ArgumentError.new("unsupported WhatsApp media kind: #{kind}")
                   end
      encrypted = Crypto.encrypt_media(plaintext, media_info)
      # whatsmeow uses base64.URLEncoding (URL-safe, WITH "=" padding) of the
      # full encrypted-file SHA256 for both the path and query token.
      token = Base64.urlsafe_encode(encrypted.file_enc_sha256)
      media_kind = kind == :image ? "image" : "document"
      query = URI::Params.encode({"auth" => @connection.auth, "token" => token})
      url = "https://#{@connection.host}/mms/#{media_kind}/#{token}?#{query}"
      headers = HTTP::Headers{
        "Origin"  => "https://web.whatsapp.com",
        "Referer" => "https://web.whatsapp.com/",
      }
      response = HTTP::Client.post(url, headers: headers, body: encrypted.ciphertext)
      raise Error.new("WhatsApp media upload failed: #{response.status_code}") unless response.success?
      payload = JSON.parse(response.body)
      UploadResponse.new(
        payload["url"].as_s,
        payload["direct_path"].as_s,
        payload["handle"]?.try(&.as_s) || "",
        payload["object_id"]?.try(&.as_s) || "",
        encrypted
      )
    end
  end
end

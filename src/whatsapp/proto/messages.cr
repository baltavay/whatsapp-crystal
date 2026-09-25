require "./writer"
require "./handshake"

module WhatsApp
  module Proto
    class ImageMessage
      property url : String?
      property mimetype : String?
      property caption : String?
      property file_sha256 : Bytes?
      property file_length : UInt64?
      property media_key : Bytes?
      property file_enc_sha256 : Bytes?
      property direct_path : String?

      def encode : Bytes
        writer = Writer.new
        writer.string(1, @url.not_nil!) if @url
        writer.string(2, @mimetype.not_nil!) if @mimetype
        writer.string(3, @caption.not_nil!) if @caption
        writer.raw(4, @file_sha256.not_nil!) if @file_sha256
        writer.uint(5, @file_length.not_nil!) if @file_length
        writer.raw(8, @media_key.not_nil!) if @media_key
        writer.raw(9, @file_enc_sha256.not_nil!) if @file_enc_sha256
        writer.string(11, @direct_path.not_nil!) if @direct_path
        writer.bytes
      end
    end

    class DocumentMessage
      property url : String?
      property mimetype : String?
      property title : String?
      property file_sha256 : Bytes?
      property file_length : UInt64?
      property media_key : Bytes?
      property file_name : String?
      property file_enc_sha256 : Bytes?
      property direct_path : String?
      property caption : String?

      def encode : Bytes
        writer = Writer.new
        writer.string(1, @url.not_nil!) if @url
        writer.string(2, @mimetype.not_nil!) if @mimetype
        writer.string(3, @title.not_nil!) if @title
        writer.raw(4, @file_sha256.not_nil!) if @file_sha256
        writer.uint(5, @file_length.not_nil!) if @file_length
        writer.raw(7, @media_key.not_nil!) if @media_key
        writer.string(8, @file_name.not_nil!) if @file_name
        writer.raw(9, @file_enc_sha256.not_nil!) if @file_enc_sha256
        writer.string(10, @direct_path.not_nil!) if @direct_path
        writer.string(20, @caption.not_nil!) if @caption
        writer.bytes
      end
    end

    class SenderKeyDistributionMessage
      property group_id : String?
      property axolotl_sender_key_distribution_message : Bytes?

      def encode : Bytes
        writer = Writer.new
        writer.string(1, @group_id.not_nil!) if @group_id
        writer.raw(2, @axolotl_sender_key_distribution_message.not_nil!) if @axolotl_sender_key_distribution_message
        writer.bytes
      end
    end

    class Message
      property conversation : String?
      property sender_key_distribution : SenderKeyDistributionMessage?
      property image : ImageMessage?
      property document : DocumentMessage?

      def encode : Bytes
        writer = Writer.new
        writer.string(1, @conversation.not_nil!) if @conversation
        if sender_key = @sender_key_distribution
          writer.raw(2, sender_key.encode)
        end
        if image = @image
          writer.raw(3, image.encode)
        end
        if document = @document
          writer.raw(7, document.encode)
        end
        writer.bytes
      end
    end

    # Decoders mirror the encoders so ciphertext produced elsewhere (tests,
    # received messages) can be inspected.
    class ImageMessage
      def self.decode(data : Bytes) : self
        message = new
        reader = Reader.new(data)
        reader.each_field do |field, wire_type|
          case field
          when 1, 2, 3, 11
            message.url = String.new(reader.bytes_field) if field == 1
            message.mimetype = String.new(reader.bytes_field) if field == 2
            message.caption = String.new(reader.bytes_field) if field == 3
            message.direct_path = String.new(reader.bytes_field) if field == 11
          when 4, 8, 9
            value = reader.bytes_field
            message.file_sha256 = value if field == 4
            message.media_key = value if field == 8
            message.file_enc_sha256 = value if field == 9
          when 5
            message.file_length = reader.uint_field
          else
            reader.skip(wire_type)
          end
        end
        message
      end
    end

    class DocumentMessage
      def self.decode(data : Bytes) : self
        message = new
        reader = Reader.new(data)
        reader.each_field do |field, wire_type|
          case field
          when 1, 2, 3, 8, 10, 20
            value = String.new(reader.bytes_field)
            case field
            when  1 then message.url = value
            when  2 then message.mimetype = value
            when  3 then message.title = value
            when  8 then message.file_name = value
            when 10 then message.direct_path = value
            when 20 then message.caption = value
            end
          when 4, 7, 9
            value = reader.bytes_field
            message.file_sha256 = value if field == 4
            message.media_key = value if field == 7
            message.file_enc_sha256 = value if field == 9
          when 5
            message.file_length = reader.uint_field
          else
            reader.skip(wire_type)
          end
        end
        message
      end
    end

    class SenderKeyDistributionMessage
      def self.decode(data : Bytes) : self
        message = new
        reader = Reader.new(data)
        reader.each_field do |field, wire_type|
          case field
          when 1
            message.group_id = String.new(reader.bytes_field)
          when 2
            message.axolotl_sender_key_distribution_message = reader.bytes_field
          else
            reader.skip(wire_type)
          end
        end
        message
      end
    end

    class Message
      def self.decode(data : Bytes) : self
        message = new
        reader = Reader.new(data)
        reader.each_field do |field, wire_type|
          case field
          when 1
            message.conversation = String.new(reader.bytes_field)
          when 2
            message.sender_key_distribution = SenderKeyDistributionMessage.decode(reader.bytes_field)
          when 3
            message.image = ImageMessage.decode(reader.bytes_field)
          when 7
            message.document = DocumentMessage.decode(reader.bytes_field)
          else
            reader.skip(wire_type)
          end
        end
        message
      end
    end
  end
end

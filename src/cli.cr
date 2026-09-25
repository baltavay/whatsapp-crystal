require "option_parser"
require "process"
require "./whatsapp"

config = WhatsApp::Config.new
action = ARGV.shift?

if action.nil? || {"help", "--help", "-h"}.includes?(action)
  puts <<-USAGE
  Usage:
    whatsapp-crystal pair [--db PATH] [--ws-url URL]
    whatsapp-crystal groups [--db PATH] [--ws-url URL]
    whatsapp-crystal logout [--db PATH] [--ws-url URL]
    whatsapp-crystal send TEXT [--group JID] [--db PATH] [--ws-url URL]
    whatsapp-crystal send-file PATH [CAPTION] [--group JID] [--db PATH] [--ws-url URL]
    whatsapp-crystal send-photo PATH [CAPTION] [--group JID] [--db PATH] [--ws-url URL]

  Environment:
    WHATSAPP_GROUP_JID     designated group, for example 123-456@g.us
    WHATSAPP_SESSION_DB    SQLite session path (default: ./whatsapp-session.db)
    WHATSAPP_WS_URL        WhatsApp WebSocket URL (default: web.whatsapp.com)
    WHATSAPP_MEDIA_HOST    optional media host override (auto-discovered when unset)
    WHATSAPP_MEDIA_AUTH    optional media token override (required with WHATSAPP_MEDIA_HOST)
  USAGE
  exit(action.nil? ? 1 : 0)
end

group = config.group_jid
db = config.session_db
ws_url = config.websocket_url
media_host = config.media_host
media_auth = config.media_auth
qr_path = nil.as(String?)

parser = OptionParser.new do |opts|
  opts.on("--group JID", "WhatsApp group JID") { |value| group = value }
  opts.on("--db PATH", "SQLite session database") { |value| db = value }
  opts.on("--ws-url URL", "WhatsApp WebSocket URL") { |value| ws_url = value }
  opts.on("--media-host HOST", "WhatsApp media host") { |value| media_host = value }
  opts.on("--media-auth TOKEN", "WhatsApp media token") { |value| media_auth = value }
  opts.on("--qr PATH", "write the pairing QR as a PNG file") { |value| qr_path = value }
  opts.on("--help", "show this help") { puts opts; exit }
end

begin
  parser.parse(ARGV)
  client = WhatsApp::Client.new(WhatsApp::Config.new(group, db, ws_url, media_host, media_auth))

  case action
  when "pair"
    puts "Scan this from WhatsApp -> Linked devices; waiting for the scan..."
    jid = client.pair_and_login do |qr|
      puts qr
      render_qr(qr, qr_path)
    end
    puts "Paired and logged in as #{jid}"
  when "groups"
    client.groups.each { |group| puts "#{group.jid}\t#{group.name}" }
  when "logout"
    puts "Unlinked #{client.logout} from the account."
  when "send"
    text = ARGV.join(" ")
    raise WhatsApp::Error.new("send requires non-empty text") if text.empty?
    client.login
    puts "Message sent: #{client.send_text(text)}"
  when "send-file", "send-photo"
    path = ARGV.shift? || raise WhatsApp::Error.new("#{action} requires a file path")
    caption = ARGV.join(" ")
    client.login
    id = action == "send-photo" ? client.send_photo(path, caption) : client.send_file(path, caption)
    puts "Message sent: #{id}"
  else
    raise WhatsApp::Error.new("unknown command: #{action}; run with --help")
  end
rescue ex : OptionParser::InvalidOption
  STDERR.puts ex.message
  exit 2
rescue ex : WhatsApp::Error
  STDERR.puts ex.message
  if ENV["WHATSAPP_DEBUG"]?
    cause = ex.is_a?(WhatsApp::Native::Error) ? ex.cause : nil
    (cause || ex).backtrace?.try { |frames| STDERR.puts frames.first(20).join("\n") }
  end
  exit 1
end

# Writes the pairing payload as a PNG via qrencode, falling back to a text file
# holding the payload when qrencode is unavailable.
private def render_qr(payload : String, path : String?) : Nil
  target = path || "./whatsapp-qr.png"
  begin
    if Process.run("qrencode", ["-o", target, payload], error: Process::Redirect::Close).success?
      puts "Scannable QR written to #{target}"
      return
    end
  rescue File::NotFoundError
    # fall through to the text fallback below
  end
  File.write(target, payload)
  puts "qrencode unavailable; the QR payload was written to #{target}"
end

# whatsapp-crystal

A pure-Crystal WhatsApp Web client: link a companion device by QR code, then
send text messages, photos and files to groups over the end-to-end encrypted
multi-device protocol. No bridges, no Go runtime — the Noise handshake, the
binary wire codec, X3DH/ratchet sessions and group sender keys are all
implemented in Crystal.

> **This is not an official WhatsApp client.** Automating WhatsApp with
> unofficial clients violates the WhatsApp Terms of Service and can get the
> phone number banned. Use at your own risk.

## Status

Working and live-verified against production servers:

- QR pairing (`<pair-device>` / `<pair-success>` handshake with ADV identity)
- Login with prekey upload, presence, app-state sync
- Group roster + device discovery (`w:g2`, `usync`)
- Text sends to groups (`pkmsg` + `skmsg`, AD-JID addressing, LID mode)
- Photo and document sends (HKDF media keys, AES-CBC + HMAC upload to the
  WhatsApp media servers)

Not implemented: receiving/decrypting messages, 1:1 chats, calls, media
retries, newsletters. The public API is send-oriented.

## Installation

Add to `shard.yml`:

```yaml
dependencies:
  whatsapp-crystal:
    github: YOUR_USERNAME/whatsapp-crystal
```

Requires Crystal >= 1.19.1 and libsqlite3 (the session store).

## Usage as a library

```crystal
require "whatsapp-crystal"

config = WhatsApp::Config.new(session_db: "./whatsapp-session.db")
client = WhatsApp::Client.new(config)

# Link a companion device: pair_and_login blocks until the QR is scanned.
jid = client.pair_and_login do |qr|
  # Render the QR payload yourself, e.g. with `qrencode -o qr.png #{qr}`
  puts "Scan this: #{qr}"
end
puts "Paired as #{jid}"

# The session is persisted; later runs only need login + send.
client.login
client.send_text("hello from Crystal", group: "120363012345678901@g.us")
client.send_photo("cat.jpg", caption: "look")
client.send_file("report.pdf", caption: "monthly")

client.groups.each { |g| puts "#{g.jid}\t#{g.name}" }

client.logout   # unlink the companion device
client.close
```

Every send returns the WhatsApp message id (a `String`). Failures raise
`WhatsApp::Error`.

### Configuration

`WhatsApp::Config` (all optional, env vars are the defaults):

| option          | env var              | default                  |
| --------------- | -------------------- | ------------------------ |
| `session_db`    | `WHATSAPP_SESSION_DB`| `./whatsapp-session.db`  |
| `group_jid`     | `WHATSAPP_GROUP_JID` | — (or pass `group:`)     |
| `websocket_url` | `WHATSAPP_WS_URL`    | `wss://web.whatsapp.com/ws/chat` |
| `media_host`    | `WHATSAPP_MEDIA_HOST`| auto-discovered          |
| `media_auth`    | `WHATSAPP_MEDIA_AUTH`| auto-discovered          |

The session database holds the identity keys, the Signal sessions and the
sender keys — treat it as a secret; deleting it loses the linking.

## Command line

The shard also ships a CLI (`src/cli.cr`):

```sh
shards build whatsapp-crystal
bin/whatsapp-crystal pair                       # link (QR to ./whatsapp-qr.png)
bin/whatsapp-crystal groups
bin/whatsapp-crystal send "hello" --group 120363012345678901@g.us
bin/whatsapp-crystal send-photo cat.jpg "caption" --group 120363012345678901@g.us
bin/whatsapp-crystal send-file report.pdf --group 120363012345678901@g.us
bin/whatsapp-crystal logout
```

`--db` selects the session database; `WHATSAPP_DEBUG=1` prints protocol
diagnostics to stderr.

## Development

```sh
shards install
crystal spec          # 50 examples: crypto vectors verified against libsignal
make build            # release CLI
```

The protocol port follows [whatsmeow](https://github.com/tulir/whatsmeow)
semantics; the Signal protocol implementation (X3DH, Double Ratchet, sender
keys, XEdDSA signatures) is cross-verified against libsignal vectors in the
spec suite.

## Contributing

Issues and pull requests are welcome. Protocol changes should come with
vectors or a live verification note.

## License

MIT — see [LICENSE](LICENSE).

require "./spec_helper"

# Drives the pairing and login state machine through the transport seam, with
# synthetic server nodes that mirror what web.whatsapp.com actually sends.
private class StubConnection < WhatsApp::Native::Connection
  getter sent = [] of WhatsApp::Binary::Node
  getter payloads = [] of Bytes
  getter queue = [] of WhatsApp::Binary::Node

  def connect(device : WhatsApp::DeviceState, client_payload : Bytes) : Nil
    @payloads << client_payload
  end

  def send(node : WhatsApp::Binary::Node) : Nil
    @sent << node
  end

  def receive(timeout : Time::Span? = nil) : WhatsApp::Binary::Node?
    @queue.empty? ? nil : @queue.shift
  end

  def request(node : WhatsApp::Binary::Node) : WhatsApp::Binary::Node?
    @sent << node
    @queue.empty? ? nil : @queue.shift
  end

  def close : Nil
  end

  def iq(type : String, id : String, children : Array(WhatsApp::Binary::Node) = [] of WhatsApp::Binary::Node) : Nil
    @queue << WhatsApp::Binary::Node.new("iq", {"from" => "s.whatsapp.net", "type" => type, "id" => id}, nil, children)
  end

  def result_for(id : String, children : Array(WhatsApp::Binary::Node) = [] of WhatsApp::Binary::Node) : Nil
    @queue << WhatsApp::Binary::Node.new("iq", {"type" => "result", "id" => id}, nil, children)
  end

  def last_sent(tag : String) : WhatsApp::Binary::Node?
    @sent.reverse.find { |node| node.tag == tag }
  end
end

# Field numbers present in a serialized ClientPayload.
private def payload_fields(payload : Bytes) : Array(Int32)
  fields = [] of Int32
  reader = WhatsApp::Proto::Reader.new(payload)
  reader.each_field do |field, wire_type|
    fields << field
    reader.skip(wire_type)
  end
  fields
end

private def with_database(&)
  path = File.join(Dir.tempdir, "whatsapp-pairing-spec-#{Random::Secure.hex(8)}.db")
  begin
    yield path
  ensure
    File.delete(path) if File.exists?(path)
  end
end

# Builds the ADV identity a primary device signs for a companion, exactly as
# <pair-success> carries it.
private def pair_success_node(device : WhatsApp::DeviceState, primary : WhatsApp::Crypto::Curve25519KeyPair, jid : String, lid : String, hmac : Bytes? = nil, raw_id : UInt64 = 4_242_u64, timestamp : UInt64 = 1_758_800_000_000_u64) : WhatsApp::Binary::Node
  details = WhatsApp::Proto::ADV::DeviceIdentity.new(
    raw_id: raw_id,
    timestamp: timestamp,
    key_index: 7_u64,
    account_type: 0_u64,
    device_type: 0_u64,
  ).encode

  signature_message = Bytes[0x06_u8, 0x00_u8] + details + device.identity_key.public_key
  account_signature = WhatsApp::Crypto::XEdDSA.sign(primary.private_key, signature_message)

  container = WhatsApp::Proto::ADV::SignedDeviceIdentity.new(
    details: details,
    account_signature_key: primary.public_key,
    account_signature: account_signature,
  ).encode
  digest = hmac || OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, device.adv_secret, container)

  device_identity = WhatsApp::Proto::ADV::SignedDeviceIdentityHMAC.new(
    details: container,
    hmac: digest,
    account_type: 0_u64,
  ).encode

  WhatsApp::Binary::Node.new("iq", {"from" => "s.whatsapp.net", "type" => "set", "id" => "pair-1"}, nil, [
    WhatsApp::Binary::Node.new("pair-success", nil, nil, [
      WhatsApp::Binary::Node.new("device-identity", nil, device_identity),
      WhatsApp::Binary::Node.new("device", {"jid" => jid, "lid" => lid}),
      WhatsApp::Binary::Node.new("platform", {"name" => "Chrome"}),
    ]),
  ])
end

describe WhatsApp::Native::Client do
  it "acknowledges the pairing request and returns a scannable QR payload" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      connection.iq("set", "req-1", [
        WhatsApp::Binary::Node.new("pair-device", nil, nil, [
          WhatsApp::Binary::Node.new("ref", nil, "2@abcDEF".to_slice),
          WhatsApp::Binary::Node.new("ref", nil, "2@ghiJKL".to_slice),
        ]),
      ])

      result = client.pair(5.seconds)
      result.success?.should be_true
      result.refs.size.should eq(2)

      qr = result.qr.not_nil!
      qr.should start_with("https://wa.me/settings/linked_devices#2@abcDEF,")
      device = client.device.not_nil!
      qr.should contain(Base64.strict_encode(device.identity_key.public_key))
      # Compliant client-type suffix: a single-character code, not a name
      # (whatsmeow issue #1110).
      qr.should end_with(",9")

      ack = connection.last_sent("iq").not_nil!
      ack.attrs["type"].should eq("result")
      ack.attrs["to"].should eq("s.whatsapp.net")
      ack.attrs["id"].should eq("req-1")
    end
  end

  it "verifies the ADV identity, signs it and persists the paired device" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!

      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")

      result = client.await_pair_success(5.seconds)
      result.paired?.should be_true
      result.error.should be_nil

      stored = device
      stored.paired?.should be_true
      stored.jid.should eq("15551234567:3@s.whatsapp.net")
      stored.lid.should eq("99999:3@lid")
      account = stored.account.not_nil!
      account.account_signature_key.should eq(primary.public_key)

      # The device signature we generated must verify as the primary expects it.
      signed_message = Bytes[0x06_u8, 0x01_u8] + account.details + device.identity_key.public_key + primary.public_key
      WhatsApp::Crypto::XEdDSA.verify(device.identity_key.public_key, signed_message, account.device_signature.not_nil!).should be_true

      confirmation = connection.sent.reverse.find { |node| node.child("pair-device-sign") }.not_nil!
      identity = confirmation.child("pair-device-sign").not_nil!.child("device-identity").not_nil!
      identity.attrs["key-index"].should eq("7")
      # The confirmation must not leak the primary account signature key.
      WhatsApp::Proto::ADV::SignedDeviceIdentity.decode(identity.content.not_nil!).account_signature_key.should be_nil

      # The paired identity survives a restart.
      reopened = WhatsApp::Native::Client.new(path, StubConnection.new)
      reopened.connect
      reopened.device.not_nil!.jid.should eq("15551234567:3@s.whatsapp.net")
    end
  end

  it "answers keepalive pings and keeps waiting through unrelated traffic" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate

      connection.queue << WhatsApp::Binary::Node.new("iq", {"from" => "s.whatsapp.net", "type" => "get", "t" => "1790335607", "xmlns" => "urn:xmpp:ping"})
      connection.queue << WhatsApp::Binary::Node.new("receipt", {"id" => "abc", "type" => "delivery"})
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")

      result = client.await_pair_success(5.seconds)
      result.paired?.should be_true
      # The ping must be answered or WhatsApp drops the socket.
      ping_reply = connection.sent.select { |node| node.attrs["type"]? == "result" && node.attrs["to"]? == "s.whatsapp.net" }
      ping_reply.should_not be_empty
    end
  end

  it "completes a pair-success IQ that carries no id" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate

      node = pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      node.attrs.delete("id")
      connection.queue << node

      result = client.await_pair_success(5.seconds)
      result.paired?.should be_true
      ack = connection.sent.reverse.find { |sent| sent.child("pair-device-sign") }.not_nil!
      ack.attrs["type"].should eq("result")
      ack.attrs.has_key?("id").should be_false
    end
  end

  it "reports the offending node when a pair-success is malformed" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      connection.queue << WhatsApp::Binary::Node.new("iq", {"type" => "set"}, nil, [
        WhatsApp::Binary::Node.new("pair-success", nil, nil, [
          WhatsApp::Binary::Node.new("device", {"jid" => "15551234567:3@s.whatsapp.net"}),
        ]),
      ])

      result = client.await_pair_success(5.seconds)
      message = result.error.not_nil!.message.to_s
      message.should contain("device-identity")
      message.should contain("pair-success")
      message.should contain("jid=15551234567:3@s.whatsapp.net")
    end
  end

  it "hands out a fresh QR when the server rotates the pairing reference" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate

      connection.iq("set", "rot-1", [
        WhatsApp::Binary::Node.new("pair-device", nil, nil, [WhatsApp::Binary::Node.new("ref", nil, "2@first".to_slice)]),
      ])
      connection.iq("set", "rot-2", [
        WhatsApp::Binary::Node.new("pair-device", nil, nil, [WhatsApp::Binary::Node.new("ref", nil, "2@second".to_slice)]),
      ])
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")

      seen = [] of String
      result = client.await_pair_success(5.seconds) { |qr| seen << qr }
      result.paired?.should be_true

      seen.size.should eq(2)
      seen.first.should contain("2@first")
      seen.last.should contain("2@second")
      connection.sent.map { |node| node.attrs["id"]? }.compact.should contain("rot-1")
      connection.sent.map { |node| node.attrs["id"]? }.compact.should contain("rot-2")
    end
  end

  it "logs in with the login payload after a completed pairing" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      client.await_pair_success(5.seconds).paired?.should be_true

      # WhatsApp drops the socket after <pair-success>; a paired companion
      # reconnects with the login payload.
      client.close
      connection.sent.clear
      client.connect
      connection.payloads.last.should_not eq(connection.payloads.first)
      connection.queue << WhatsApp::Binary::Node.new("success", {"lid" => "99999:3@lid"})
      connection.result_for("count")
      connection.result_for("prekeys")
      connection.result_for("passive")

      client.login(5.seconds).success?.should be_true
      client.logged_in?.should be_true
    end
  end

  it "acknowledges inbound messages so the offline queue drains" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      connection.queue << WhatsApp::Binary::Node.new("message", {
        "from"        => "120363433640733657@g.us",
        "id"          => "AC031F2A08C9517DA4F87B6781928A13",
        "type"        => "text",
        "participant" => "46179622641867@lid",
      })
      client.pair(50.milliseconds)

      ack = connection.sent.find { |node| node.tag == "ack" }.not_nil!
      ack.attrs["class"].should eq("message")
      ack.attrs["id"].should eq("AC031F2A08C9517DA4F87B6781928A13")
      ack.attrs["to"].should eq("120363433640733657@g.us")
      ack.attrs["participant"].should eq("46179622641867@lid")
    end
  end

  it "unlinks the companion through remove-companion-device" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      client.await_pair_success(5.seconds).paired?.should be_true
      connection.queue << WhatsApp::Binary::Node.new("success", {"lid" => "99999:3@lid"})
      connection.result_for("count")
      connection.result_for("prekeys")
      connection.result_for("passive")
      client.login(5.seconds).success?.should be_true
      connection.sent.clear

      connection.queue << WhatsApp::Binary::Node.new("iq", {"type" => "result", "id" => "x"})
      result = client.logout
      result.success?.should be_true

      request = connection.sent.find { |node| node.child("remove-companion-device") }.not_nil!
      request.attrs["xmlns"].should eq("md")
      request.attrs["type"].should eq("set")
      removal = request.child("remove-companion-device").not_nil!
      removal.attrs["jid"].should eq("15551234567:3@s.whatsapp.net")
      removal.attrs["reason"].should eq("user_initiated")

      # Logout wipes the store (whatsmeow Store.Delete): the identity must not
      # survive as a phantom linked session in the database.
      WhatsApp::Store::DeviceStore.new(path).load_or_create.jid.should be_nil
    end
  end

  it "pings the server as keepalive and reports the round trip" do
    with_database do |path|
      previous = ENV["WHATSAPP_REQUEST_TIMEOUT"]?
      ENV["WHATSAPP_REQUEST_TIMEOUT"] = "1"
      begin
        connection = StubConnection.new
        client = WhatsApp::Native::Client.new(path, connection)
        client.connect
        device = client.device.not_nil!
        primary = WhatsApp::Crypto::Curve25519KeyPair.generate
        connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
        client.await_pair_success(5.seconds).paired?.should be_true
        # The unified-session id is reported on the pairing socket right after
        # the pair-device-sign confirmation.
        pairing_ib = connection.sent.find { |node| node.tag == "ib" && node.child("unified_session") }.not_nil!
        pairing_id = pairing_ib.child("unified_session").not_nil!.attribute("id").to_s
        pairing_id.should match(/^\d+$/)
        pairing_id.to_i64.should be < 604_800_000
        connection.queue << WhatsApp::Binary::Node.new("success", {"lid" => "99999:3@lid"})
        connection.result_for("count")
        connection.result_for("prekeys")
        connection.result_for("passive")
        client.login(5.seconds).success?.should be_true
        # Presence-available after login reports the unified-session id again
        # on the logged-in connection.
        login_ibs = connection.sent.count { |node| node.tag == "ib" && node.child("unified_session") }
        login_ibs.should eq 2
        connection.sent.clear

        # A socket that never answers is a dead socket, not a hang.
        client.ping.should be_false
        ping = connection.sent.reverse.find { |node| node.attribute("xmlns") == "urn:xmpp:ping" }.not_nil!
        ping.attribute("type").should eq("get")
        ping.attribute("to").should eq("s.whatsapp.net")
        ping.child("ping").not_nil!
        # A result IQ answers the round trip. The reply carries no id: an
        # id-less response matches whichever request is waiting.
        connection.queue << WhatsApp::Binary::Node.new("iq", {"type" => "result"})
        client.ping.should be_true
      ensure
        ENV.delete("WHATSAPP_REQUEST_TIMEOUT")
        ENV["WHATSAPP_REQUEST_TIMEOUT"] = previous if previous
      end
    end
  end

  it "refuses login when no device is linked" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      result = client.login
      (result.error.not_nil!.message || "").should contain("not linked")
      connection.sent.empty?.should be_true
    end
  end

  it "syncs flagged app-state collections and marks dirty flags clean" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      client.await_pair_success(5.seconds).paired?.should be_true

      connection.queue << WhatsApp::Binary::Node.new("success", {"lid" => "99999:3@lid"})
      # Initial bootstrap: dirty flag plus a collection the server wants synced.
      connection.queue << WhatsApp::Binary::Node.new("ib", {"from" => "s.whatsapp.net"}, nil, [
        WhatsApp::Binary::Node.new("dirty", {"type" => "account_sync", "timestamp" => "1790337810"}),
      ])
      connection.queue << WhatsApp::Binary::Node.new("notification", {"type" => "server_sync", "t" => "1790337811"}, nil, [
        WhatsApp::Binary::Node.new("collection", {"name" => "regular_low", "version" => "36"}),
      ])
      connection.result_for("clean")
      connection.result_for("collection")
      connection.result_for("count")
      connection.result_for("prekeys")
      connection.result_for("passive")

      client.login(5.seconds).success?.should be_true

      clean = connection.sent.find { |node| node.child("clean") }.not_nil!
      clean.attribute("xmlns").should eq("urn:xmpp:whatsapp:dirty")
      clean.attribute("type").should eq("set")
      clean.child("clean").not_nil!.attrs["type"].should eq("account_sync")
      clean.child("clean").not_nil!.attrs["timestamp"].should eq("1790337810")

      sync = connection.sent.find { |node| node.attribute("xmlns") == "w:sync:app:state" }.not_nil!
      sync.attribute("type").should eq("set")
      sync.attribute("to").should eq("s.whatsapp.net")
      collection = sync.child("sync").not_nil!.child("collection").not_nil!
      collection.attrs["name"].should eq("regular_low")
      collection.attrs["return_snapshot"].should eq("true")
    end
  end

  it "surfaces a login failure node instead of pretending to be logged in" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      client.await_pair_success(5.seconds).paired?.should be_true
      connection.queue << WhatsApp::Binary::Node.new("failure", {"reason" => "401", "message" => "bad"})

      result = client.login(5.seconds)
      result.error.not_nil!.kind.should eq(:login)
      result.error.not_nil!.message.to_s.should contain("401")
      client.logged_in?.should be_false
    end
  end

  it "times out cleanly when the server never sends a pairing request" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      result = client.pair(50.milliseconds)
      result.success?.should be_false
      result.error.not_nil!.message.to_s.should contain("timed out")
    end
  end

  it "rejects a pair-success whose HMAC does not match our ADV secret" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate

      connection.queue << pair_success_node(device, primary, "1:3@s.whatsapp.net", "2:3@lid", hmac: Bytes.new(32))

      result = client.await_pair_success(5.seconds)
      result.error.not_nil!.message.to_s.should contain("HMAC")
      device.paired?.should be_false
    end
  end

  it "uploads prekeys and leaves passive mode after login success" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      client.await_pair_success(5.seconds)
      connection.sent.clear

      connection.queue << WhatsApp::Binary::Node.new("success", {"lid" => "99999:3@lid"})
      connection.result_for("count")
      connection.result_for("ignored")
      connection.result_for("ignored")

      result = client.login(5.seconds)
      result.success?.should be_true
      client.logged_in?.should be_true

      # The post-login sequence asks for the server prekey count, then uploads.
      count = connection.sent.find { |node| node.tag == "iq" && node.child("count") }.not_nil!
      count.attribute("xmlns").should eq("encrypt")
      count.attribute("type").should eq("get")
      upload = connection.sent.find { |node| node.tag == "iq" && node.attribute("xmlns") == "encrypt" && node.attribute("type") == "set" }.not_nil!
      upload.child("registration").should_not be_nil
      upload.child("registration").not_nil!.content.not_nil!.size.should eq(4)
      upload.child("type").not_nil!.content.not_nil!.should eq(Bytes[5_u8])
      upload.child("identity").not_nil!.content.not_nil!.should eq(device.identity_key.public_key)
      list = upload.child("list").not_nil!
      list.children.size.should eq(WhatsApp::DeviceState::INITIAL_PREKEY_COUNT)
      first = list.children.first
      first.child("id").not_nil!.content.not_nil!.size.should eq(3)
      first.child("value").not_nil!.content.not_nil!.size.should eq(32)
      signed = upload.child("skey").not_nil!
      signature = signed.child("signature").not_nil!.content.not_nil!
      WhatsApp::Crypto::XEdDSA.verify(device.identity_key.public_key, WhatsApp::PreKey.signature_input(device.signed_prekey.public_key), signature).should be_true

      passive = connection.sent.find { |node| node.tag == "iq" && node.attribute("xmlns") == "passive" }.not_nil!
      passive.child("active").should_not be_nil
      # Presence carries the pushname the server needs for this companion.
      presence = connection.sent.find { |node| node.tag == "presence" }.not_nil!
      presence.attrs["type"].should eq("available")
      presence.attrs["name"].should eq("Crystal")
      # Prekeys are only uploaded once.
      device.unuploaded_prekeys.size.should eq(0)
    end
  end

  it "sends the registration payload before pairing and the login payload after" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection)
      client.connect
      registration = connection.payloads.first.not_nil!
      fields = payload_fields(registration)
      fields.should contain(19)     # devicePairingData
      fields.should_not contain(18) # device id, only sent by paired companions

      device = client.device.not_nil!
      primary = WhatsApp::Crypto::Curve25519KeyPair.generate
      connection.queue << pair_success_node(device, primary, "15551234567:3@s.whatsapp.net", "99999:3@lid")
      client.await_pair_success(5.seconds)

      connection.payloads.clear
      client.close
      logged_in_client = WhatsApp::Native::Client.new(path, connection)
      logged_in_client.connect
      login = connection.payloads.last.not_nil!
      login.should_not eq(registration)
      login_fields = payload_fields(login)
      login_fields.should contain(1)  # username
      login_fields.should contain(18) # device id
      login_fields.should_not contain(19)
    end
  end
end

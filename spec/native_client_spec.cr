require "./spec_helper"

# Records every node handed to the transport and replays queued server nodes,
# so the pairing, login and send paths are exercised without a socket.
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

  def push(node : WhatsApp::Binary::Node) : Nil
    @queue << node
  end

  def result(id : String = "r") : Nil
    @queue << WhatsApp::Binary::Node.new("iq", {"type" => "result", "id" => id})
  end

  def find(tag : String) : WhatsApp::Binary::Node?
    @sent.reverse.find { |node| node.tag == tag }
  end
end

private class StubGroupCrypto < WhatsApp::GroupCrypto
  getter distributions = [] of String
  getter plaintexts = [] of Bytes

  def distribution(group_jid : String) : Bytes
    @distributions << group_jid
    "skdm-for-#{group_jid}".to_slice
  end

  def encrypt(group_jid : String, plaintext : Bytes) : Bytes
    @plaintexts << plaintext
    "skmsg-body".to_slice
  end
end

private class StubPairwiseCrypto < WhatsApp::PairwiseCrypto
  getter encrypts = [] of Tuple(String, Bytes)
  getter bundles = [] of WhatsApp::PreKeyBundle?
  # Devices that already have a session; others trigger a bundle fetch.
  property established : Array(String)

  def initialize(@established = [] of String)
  end

  def session?(device_jid : String) : Bool
    @established.includes?(device_jid)
  end

  def encrypt(device_jid : String, bundle : WhatsApp::PreKeyBundle?, plaintext : Bytes) : Tuple(String, Bytes)
    @encrypts << {device_jid, plaintext}
    @bundles << bundle
    {"pkmsg", "pairwise-for-#{device_jid}".to_slice}
  end
end

private class StubMediaTransport < WhatsApp::Native::MediaTransport
  getter uploads = [] of String

  def upload(path : String, kind : Symbol, mime_type : String?) : WhatsApp::UploadResponse
    @uploads << "#{kind}:#{path}"
    encrypted = WhatsApp::Crypto.encrypt_media(File.read(path).to_slice, "WhatsApp Image Keys")
    WhatsApp::UploadResponse.new("https://mmg.example/upload", "/v/token", "handle", "object", encrypted)
  end
end

# The serialized ADV identity the client must advertise when it distributes
# a fresh sender key.
private def device_account_identity(client) : Bytes
  client.device.not_nil!.account.not_nil!.encode
end

private def with_database(&)
  path = File.join(Dir.tempdir, "whatsapp-native-spec-#{Random::Secure.hex(8)}.db")
  begin
    yield path
  ensure
    File.delete(path) if File.exists?(path)
  end
end

SPEC_GROUP = "1234567890-1234567890@g.us"
private DEVICE_ONE = "15551234567:1@s.whatsapp.net"
private DEVICE_TWO = "15557654321:7@s.whatsapp.net"

# Drives connect + pairing + login so the client is ready to send.
private def logged_in_client(path : String, connection : StubConnection, group_crypto : StubGroupCrypto, pairwise : StubPairwiseCrypto, media : WhatsApp::Native::MediaTransport? = nil)
  client = WhatsApp::Native::Client.new(path, connection, media, group_crypto, pairwise)
  client.connect
  device = client.device.not_nil!

  primary = WhatsApp::Crypto::Curve25519KeyPair.generate
  details = WhatsApp::Proto::ADV::DeviceIdentity.new(
    raw_id: 1_u64,
    timestamp: Time.utc.to_unix.to_u64,
    key_index: 3_u64,
    account_type: 0_u64,
    device_type: 0_u64,
  ).encode
  account_signature = WhatsApp::Crypto::XEdDSA.sign(primary.private_key, Bytes[0x06_u8, 0x00_u8] + details + device.identity_key.public_key)
  container = WhatsApp::Proto::ADV::SignedDeviceIdentity.new(
    details: details,
    account_signature_key: primary.public_key,
    account_signature: account_signature,
  ).encode
  hmac = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, device.adv_secret, container)
  connection.push(WhatsApp::Binary::Node.new("iq", {"from" => "s.whatsapp.net", "type" => "set", "id" => "p1"}, nil, [
    WhatsApp::Binary::Node.new("pair-success", nil, nil, [
      WhatsApp::Binary::Node.new("device-identity", nil, WhatsApp::Proto::ADV::SignedDeviceIdentityHMAC.new(details: container, hmac: hmac, account_type: 0_u32).encode),
      WhatsApp::Binary::Node.new("device", {"jid" => "15550000000:3@s.whatsapp.net", "lid" => "15550000000:3@lid"}),
    ]),
  ]))
  client.await_pair_success(5.seconds).paired?.should be_true

  connection.push(WhatsApp::Binary::Node.new("success", {"lid" => "15550000000:3@lid"}))
  connection.result
  connection.result
  client.login(5.seconds).success?.should be_true
  connection.sent.clear
  client
end

describe WhatsApp::Sender do
  it "addresses the group's devices and sends the sender-key ciphertext" do
    with_database do |path|
      connection = StubConnection.new
      group_crypto = StubGroupCrypto.new
      pairwise = StubPairwiseCrypto.new(established: [DEVICE_TWO])
      client = logged_in_client(path, connection, group_crypto, pairwise)

      connection.push(WhatsApp::Binary::Node.new("iq", {"type" => "result"}, nil, [
        WhatsApp::Binary::Node.new("group", {"addressing_mode" => "lid"}, nil, [
          WhatsApp::Binary::Node.new("participant", {"jid" => "15551234567@s.whatsapp.net"}),
          WhatsApp::Binary::Node.new("participant", {"jid" => "15557654321@s.whatsapp.net"}),
        ]),
      ]))
      connection.push(WhatsApp::Binary::Node.new("iq", {"type" => "result"}, nil, [
        WhatsApp::Binary::Node.new("usync", nil, nil, [
          WhatsApp::Binary::Node.new("list", nil, nil, [
            WhatsApp::Binary::Node.new("user", {"jid" => "15551234567@s.whatsapp.net"}, nil, [
              WhatsApp::Binary::Node.new("devices", nil, nil, [
                WhatsApp::Binary::Node.new("device-list", nil, nil, [
                  WhatsApp::Binary::Node.new("device", {"id" => "0"}),
                  WhatsApp::Binary::Node.new("device", {"id" => "1"}),
                ]),
              ]),
            ]),
            WhatsApp::Binary::Node.new("user", {"jid" => "15557654321@s.whatsapp.net"}, nil, [
              WhatsApp::Binary::Node.new("devices", nil, nil, [
                WhatsApp::Binary::Node.new("device-list", nil, nil, [
                  WhatsApp::Binary::Node.new("device", {"id" => "0"}),
                  WhatsApp::Binary::Node.new("device", {"id" => "7"}),
                ]),
              ]),
            ]),
          ]),
        ]),
      ]))
      # Device one has no session, so a bundle is fetched for it.
      keys = WhatsApp::Binary::Node.new("keys", nil, nil, [
        WhatsApp::Binary::Node.new("registration", nil, Bytes[0_u8, 0_u8, 0_u8, 9_u8]),
        WhatsApp::Binary::Node.new("identity", nil, Bytes.new(32) { |i| i.to_u8 }),
        WhatsApp::Binary::Node.new("skey", nil, nil, [
          WhatsApp::Binary::Node.new("id", nil, Bytes[0_u8, 0_u8, 1_u8]),
          WhatsApp::Binary::Node.new("value", nil, Bytes.new(32) { |i| (i + 1).to_u8 }),
          WhatsApp::Binary::Node.new("signature", nil, Bytes.new(64) { |i| i.to_u8 }),
        ]),
      ])
      connection.push(WhatsApp::Binary::Node.new("iq", {"type" => "result"}, nil, [
        WhatsApp::Binary::Node.new("list", nil, nil, [
          WhatsApp::Binary::Node.new("user", {"jid" => DEVICE_ONE}, nil, [keys]),
        ]),
      ]))
      connection.result("send")

      result = client.send_text(SPEC_GROUP, "hello group")
      result.success?.should be_true

      message = connection.find("message").not_nil!
      message.attrs["to"].should eq(SPEC_GROUP)
      message.attrs["type"].should eq("text")
      message.attrs["id"].should eq(result.id)
      message.attrs["id"].should match(/\A3EB0[0-9A-F]{16}\z/)
      message.attrs["phash"].should match(/\A2:[A-Za-z0-9+\/]{8}\z/)
      # LID groups carry the mode, and distributing a new sender key requires
      # our ADV device identity alongside the participants.
      message.attrs["addressing_mode"].should eq("lid")
      identity = message.child("device-identity").not_nil!
      identity.content.should eq(device_account_identity(client))

      participants = message.child("participants").not_nil!
      # Device 0 arrives in the canonical "user@server" form, others keep their suffix.
      participants.children.map { |node| node.attrs["jid"] }.should eq(["15551234567@s.whatsapp.net", DEVICE_ONE, "15557654321@s.whatsapp.net", DEVICE_TWO])
      participants.children.each do |node|
        enc = node.child("enc").not_nil!
        enc.attrs["type"].should eq("pkmsg")
        enc.attrs["v"].should eq("2")
      end

      # The distribution message goes out pairwise, addressed to the group:
      # two users, each with a device-0 (canonical form) and one companion.
      pairwise.encrypts.size.should eq(4)
      distribution = WhatsApp::Proto::Message.decode(WhatsApp::Sender.unpad_message(pairwise.encrypts.first[1]))
      sender_key = distribution.sender_key_distribution.not_nil!
      sender_key.group_id.should eq(SPEC_GROUP)
      sender_key.axolotl_sender_key_distribution_message.should eq("skdm-for-#{SPEC_GROUP}".to_slice)
      # Only devices without a session needed a bundle; the stub answered for
      # DEVICE_ONE only.
      pairwise.bundles.compact.size.should eq(1)
      pairwise.encrypts.map { |(jid, _plaintext)| jid }.should eq([
        "15551234567@s.whatsapp.net", DEVICE_ONE, "15557654321@s.whatsapp.net", DEVICE_TWO,
      ])

      # The discovery and bundle requests must match whatsmeow's shapes.
      usync = connection.sent.find { |node| node.tag == "iq" && node.attribute("xmlns") == "usync" }.not_nil!
      usync_query = usync.child("usync").not_nil!
      usync_query.attrs["mode"].should eq("query")
      usync_query.attrs["context"].should eq("message")
      usync_query.child("query").not_nil!.child("devices").not_nil!.attrs["version"].should eq("2")
      usync_query.child("list").not_nil!.children.map { |node| node.attrs["jid"] }.should eq(["15551234567@s.whatsapp.net", "15557654321@s.whatsapp.net"])

      group_iq = connection.sent.find { |node| node.tag == "iq" && node.attribute("xmlns") == "w:g2" }.not_nil!
      group_iq.attrs["to"].should eq(SPEC_GROUP)
      group_iq.child("query").not_nil!.attrs["request"].should eq("interactive")

      bundle_iq = connection.sent.find { |node| node.tag == "iq" && node.attribute("xmlns") == "encrypt" }.not_nil!
      bundle_users = bundle_iq.child("key").not_nil!.children
      bundle_users.map { |node| node.attrs["jid"] }.should contain(DEVICE_ONE)
      bundle_users.map { |node| node.attrs["reason"] }.uniq.should eq(["identity"])

      enc = message.child("enc").not_nil!
      enc.attrs["type"].should eq("skmsg")
      enc.attrs["mediatype"]?.should be_nil
      enc.content.should eq("skmsg-body".to_slice)
      # Plaintext must carry libsignal's padding, or receivers truncate it.
      padded = group_crypto.plaintexts.first
      WhatsApp::Sender.unpad_message(padded).should eq(WhatsApp::Proto::Message.new.tap(&.conversation = "hello group").encode)
      pad_count = padded[padded.size - 1].to_i
      pad_count.should be >= 1
      padded[-pad_count, pad_count].should eq(Bytes.new(pad_count) { pad_count.to_u8 })
    end
  end

  it "wraps an uploaded photo in an image message" do
    with_database do |path|
      file = File.tempname("photo", ".jpg")
      File.write(file, "fake jpeg bytes")
      begin
        connection = StubConnection.new
        group_crypto = StubGroupCrypto.new
        pairwise = StubPairwiseCrypto.new(established: ["15557654321@s.whatsapp.net", DEVICE_TWO])
        media = StubMediaTransport.new
        client = logged_in_client(path, connection, group_crypto, pairwise, media)

        connection.push(WhatsApp::Binary::Node.new("iq", {"type" => "result"}, nil, [
          WhatsApp::Binary::Node.new("group", nil, nil, [
            WhatsApp::Binary::Node.new("participant", {"jid" => "15557654321@s.whatsapp.net"}),
          ]),
        ]))
        connection.push(WhatsApp::Binary::Node.new("iq", {"type" => "result"}, nil, [
          WhatsApp::Binary::Node.new("usync", nil, nil, [
            WhatsApp::Binary::Node.new("list", nil, nil, [
              WhatsApp::Binary::Node.new("user", {"jid" => "15557654321@s.whatsapp.net"}, nil, [
                WhatsApp::Binary::Node.new("devices", nil, nil, [
                  WhatsApp::Binary::Node.new("device-list", nil, nil, [
                    WhatsApp::Binary::Node.new("device", {"id" => "0"}),
                    WhatsApp::Binary::Node.new("device", {"id" => "7"}),
                  ]),
                ]),
              ]),
            ]),
          ]),
        ]))
        connection.result("send")

        result = client.send_photo(SPEC_GROUP, file, "caption")
        result.success?.should be_true
        media.uploads.should eq(["image:#{file}"])

        message = connection.find("message").not_nil!
        message.attrs["type"].should eq("media")
        message.child("enc").not_nil!.attrs["mediatype"].should eq("image")

        plaintext = WhatsApp::Sender.unpad_message(group_crypto.plaintexts.last)
        image = WhatsApp::Proto::Message.decode(plaintext).image.not_nil!
        image.caption.should eq("caption")
        image.url.should eq("https://mmg.example/upload")
        image.mimetype.should eq("image/jpeg")
        image.file_length.should eq(15_u64)
      ensure
        File.delete(file) if File.exists?(file)
      end
    end
  end

  it "reports a missing file instead of sending an empty media message" do
    with_database do |path|
      connection = StubConnection.new
      client = logged_in_client(path, connection, StubGroupCrypto.new, StubPairwiseCrypto.new, StubMediaTransport.new)
      result = client.send_document(SPEC_GROUP, "/nonexistent/file.pdf")
      result.error.not_nil!.kind.should eq(:send_document)
    end
  end

  it "parses group listings returned by the transport" do
    with_database do |path|
      connection = StubConnection.new
      client = logged_in_client(path, connection, StubGroupCrypto.new, StubPairwiseCrypto.new)
      # Shape taken from the live group server: the group node carries a numeric
      # id, not a JID.
      connection.push(WhatsApp::Binary::Node.new("iq", {"from" => "g.us", "type" => "result"}, nil, [
        WhatsApp::Binary::Node.new("groups", nil, nil, [
          WhatsApp::Binary::Node.new("group", {"addressing_mode" => "lid", "id" => "120363433640733657", "subject" => "Team"}),
          WhatsApp::Binary::Node.new("group", {"addressing_mode" => "lid", "id" => "996772423868-1458535172", "subject" => "Дети"}),
        ]),
      ]))

      groups = client.groups
      groups.success?.should be_true
      groups.groups.map(&.jid).should eq(["120363433640733657@g.us", "996772423868-1458535172@g.us"])
      groups.groups.map(&.name).should eq(["Team", "Дети"])
    end
  end

  it "refuses to send before the client is logged in" do
    with_database do |path|
      connection = StubConnection.new
      client = WhatsApp::Native::Client.new(path, connection, nil, StubGroupCrypto.new, StubPairwiseCrypto.new)
      client.connect
      client.send_text(SPEC_GROUP, "too early").error.not_nil!.kind.should eq(:not_connected)
    end
  end
end

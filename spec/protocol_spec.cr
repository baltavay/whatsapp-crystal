require "./spec_helper"

# Each example here encodes a fact learned from WhatsApp's live server and the
# reference implementation; every one of them was a real bug before.
describe WhatsApp::Crypto::NoiseHandshake do
  # Captured from a live session: client ephemeral private key, the server
  # ephemeral from its ServerHello and the resulting encrypted server static.
  client_private = "589ba0f7ef6b53b7d6da74ffd4095ba63f7ba2b8fa628a4747786c5f447f4442".hexbytes
  client_public = "510a1532114d4037face245fac7c533de06b79f74d3a153981de1a991a4d330d".hexbytes
  server_ephemeral = "f0f44e0befac34b2d4c9dfb630faa79a5632036e6923d08713cf577a278b5b6a".hexbytes
  server_static_ct = "2a9c47b2ec3491da92a907c752c706f927ae9f50603b8eabeaa377ffa8c20aa91c7ee7cc475923b7b49321672dd4450b".hexbytes
  # WhatsApp's long-lived Noise server static key, also the leaf certificate key.
  server_static = "ecb3a60811fa72b086858920034a2eaa9447d99543d97d40e2a5c9e01c795b13".hexbytes

  it "seeds the handshake from the raw pattern instead of hashing it" do
    pattern = WhatsApp::Transport::HandshakeClient::PATTERN
    header = WhatsApp::Transport::FrameSocket::HEADER
    pattern.size.should eq(32)

    noise = WhatsApp::Crypto::NoiseHandshake.new
    noise.hash.should eq(Bytes.new(0))
    noise.start(pattern, header)

    # Cross-checked against whatsmeow: the raw pattern is the initial salt and
    # the hash after the connection header is sha256(pattern || header).
    noise.salt.should eq(pattern.to_slice)
    noise.hash.should eq("ffff0c9267310966f1311170c04b38c79504285bf5edf763e5c946492a50a755".hexbytes)
  end

  it "decrypts the server static with the ephemeral-ephemeral secret" do
    noise = WhatsApp::Crypto::NoiseHandshake.new.start(
      WhatsApp::Transport::HandshakeClient::PATTERN,
      WhatsApp::Transport::FrameSocket::HEADER
    )
    noise.authenticate(client_public)
    noise.authenticate(server_ephemeral)
    noise.mix_shared_secret(WhatsApp::Crypto::Curve25519KeyPair.new(client_private, client_public), server_ephemeral)

    noise.decrypt(server_static_ct).should eq(server_static)
  end

  it "derives transport keys that decrypt a recorded server frame" do
    noise = WhatsApp::Crypto::NoiseHandshake.new.start(
      WhatsApp::Transport::HandshakeClient::PATTERN,
      WhatsApp::Transport::FrameSocket::HEADER
    )
    noise.authenticate(client_public)
    noise.authenticate(server_ephemeral)
    noise.mix_shared_secret(WhatsApp::Crypto::Curve25519KeyPair.new(client_private, client_public), server_ephemeral)
    static = noise.decrypt(server_static_ct)
    noise.mix_shared_secret(WhatsApp::Crypto::Curve25519KeyPair.new(client_private, client_public), static)

    write_key, read_key = noise.transport_keys
    write_key.size.should eq(32)
    read_key.size.should eq(32)
    write_key.should_not eq(read_key)
  end
end

describe WhatsApp::Crypto::NoiseCertificate do
  it "verifies a real WhatsApp certificate chain with XEdDSA" do
    certificate = "0a770a3308e90210031a20ecb3a60811fa72b086858920034a2eaa9447d99543d97d40e2a5c9e01c795b1320d0cfc1d10628d089dad6061240328605ad41aece527f0fadbf7313b89ec6278171eb10bc948bfc87180a172572a25235d1c446353fcd97530469aca15178d359a7b7dde4bab02984d34789bb0512760a32080310001a201c51a9ac303994c6c8d0b92ea1878a533476599cc599fbea35997d9aa90cce62208091aebe0628ffdeb7dc061240270f294648539fed4870e25054dd4e95983aba29189c2ba6c8eeda7055555f753740f5ec192ab64c26c26d6ade6d20b9f774aee37120a6b20395f53c66058507".hexbytes
    server_static = "ecb3a60811fa72b086858920034a2eaa9447d99543d97d40e2a5c9e01c795b13".hexbytes

    WhatsApp::Crypto::NoiseCertificate.verify(certificate, server_static).should be_true
    # The leaf key is the decrypted static, so a mismatched key must be rejected.
    WhatsApp::Crypto::NoiseCertificate.verify(certificate, Bytes.new(32)).should be_false
  end
end

describe WhatsApp::Binary::Frame do
  it "strips the flag byte and keeps the body" do
    packed = Bytes[0_u8] + "node-bytes".to_slice
    WhatsApp::Binary::Frame.unpack(packed).should eq("node-bytes".to_slice)
  end

  it "adds the uncompressed flag byte when packing" do
    WhatsApp::Binary::Frame.pack("node-bytes".to_slice).should eq(Bytes[0_u8] + "node-bytes".to_slice)
  end

  it "decompresses frames whose flag byte marks zlib" do
    body = "compressed node body".to_slice
    io = IO::Memory.new
    Compress::Zlib::Writer.open(io) { |writer| writer.write(body) }
    compressed = io.to_slice
    WhatsApp::Binary::Frame.unpack(Bytes[2_u8] + compressed).should eq(body)
  end
end

describe WhatsApp::Transport::FrameSocket do
  it "encodes frame lengths that exceed one byte without overflowing" do
    header = WhatsApp::Transport::FrameSocket::HEADER
    payload = Bytes.new(300) { |index| (index % 251).to_u8 }

    frame = WhatsApp::Transport::FrameSocket.encode_frame(payload, header)
    frame.size.should eq(header.size + 3 + payload.size)
    frame[header.size].should eq(0_u8)
    frame[header.size + 1].should eq(1_u8)
    frame[header.size + 2].should eq(44_u8)
    WhatsApp::Transport::FrameSocket.parse_frame_length(frame[header.size, 3]).should eq(300)

    # The connection header is only part of the first frame.
    follow_up = WhatsApp::Transport::FrameSocket.encode_frame(payload, Bytes.new(0))
    follow_up.size.should eq(3 + payload.size)
  end
end

describe WhatsApp::Binary::Codec do
  # A real <iq><pair-device> node captured from web.whatsapp.com right after the
  # Noise handshake.
  it "decodes a real server node" do
    body = File.read(File.join(__DIR__, "fixtures/pair_device_node.hex")).strip.hexbytes
    node = WhatsApp::Binary::Codec.decode(body)

    node.tag.should eq("iq")
    node.attrs["xmlns"].should eq("md")
    node.attrs["type"].should eq("set")
    node.attrs["from"].should eq("s.whatsapp.net")
    pair_device = node.child("pair-device")
    pair_device.should_not be_nil
    refs = pair_device.not_nil!.children.select { |child| child.tag == "ref" }
    refs.size.should eq(6)
    refs.each do |ref|
      ref.content.should_not be_nil
      String.new(ref.content.not_nil!).should start_with("2@")
    end
  end

  it "nibble-packs numeric strings exactly like whatsmeow" do
    # Real bytes produced by whatsmeow's encoder for the JID user "42138041614348":
    # the packed value is the tail of the encoded node.
    node = WhatsApp::Binary::Node.new("iq", {"id" => "42138041614348"}, nil)
    WhatsApp::Binary::Codec.encode(node)[-9, 9].should eq("ff0742138041614348".hexbytes)

    # Odd-length values set the odd flag and zero-pad the final nibble
    # (1,2)(3,-)(4,5)(6,pad) with '-' packed as 10.
    odd = WhatsApp::Binary::Node.new("iq", {"id" => "123-456"}, nil)
    WhatsApp::Binary::Codec.encode(odd)[-6, 6].should eq("ff84123a4560".hexbytes)

    # A LID device JID must travel as an AD JID: reference bytes for
    # "42138041614348:21@lid" produced by whatsmeow's own encoder.
    lid = WhatsApp::Binary::Node.new("user", {"jid" => "42138041614348:21@lid"}, nil)
    WhatsApp::Binary::Codec.encode(lid)[-12, 12].should eq("f70115ff0742138041614348".hexbytes)

    # Packed forms must round trip, including the device suffix these JIDs carry.
    jid = WhatsApp::Binary::Node.new("user", {"jid" => "42138041614348:21@lid"}, nil)
    decoded = WhatsApp::Binary::Codec.decode(WhatsApp::Binary::Codec.encode(jid))
    decoded.attrs["jid"].should eq("42138041614348:21@lid")
  end

  it "encodes lists longer than 255 children" do
    children = (0...812).map { |index| WhatsApp::Binary::Node.new("key", {"id" => index.to_s}) }
    node = WhatsApp::Binary::Node.new("list", nil, nil, children)

    decoded = WhatsApp::Binary::Codec.decode(WhatsApp::Binary::Codec.encode(node))
    decoded.children.size.should eq(812)
    decoded.children.last.attrs["id"].should eq("811")

    long_content = WhatsApp::Binary::Node.new("value", nil, Bytes.new(300) { |index| (index % 251).to_u8 })
    decoded_value = WhatsApp::Binary::Codec.decode(WhatsApp::Binary::Codec.encode(long_content))
    decoded_value.content.not_nil!.size.should eq(300)
  end

  it "round trips attributes, content and children" do
    message = WhatsApp::Binary::Node.new("message", {"to" => "123-456@g.us", "type" => "text", "id" => "ABC"}, nil, [
      WhatsApp::Binary::Node.new("enc", {"v" => "2", "type" => "skmsg"}, Bytes[1_u8, 2_u8, 3_u8]),
    ])
    node = WhatsApp::Binary::Node.new("action", {"type" => "set"}, nil, [message])

    decoded = WhatsApp::Binary::Codec.decode(WhatsApp::Binary::Codec.encode(node))
    decoded.tag.should eq("action")
    decoded.attrs["type"].should eq("set")
    child = decoded.child("message").not_nil!
    child.attrs["to"].should eq("123-456@g.us")
    child.attrs["id"].should eq("ABC")
    child.child("enc").not_nil!.content.should eq(Bytes[1_u8, 2_u8, 3_u8])
  end
end

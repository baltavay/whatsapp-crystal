require "./spec_helper"
require "base64"

private def fixed_group_signing_pair : WhatsApp::Crypto::Curve25519KeyPair
  private_key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".hexbytes
  public_key = Bytes.new(32)
  WhatsApp::Crypto.ensure_sodium
  result = WhatsApp::Crypto::LibSodium.crypto_scalarmult_curve25519_base(public_key, private_key)
  raise "fixed sender-key public key derivation failed" unless result == 0
  WhatsApp::Crypto::Curve25519KeyPair.new(private_key, public_key)
end

private def fixed_group_record : WhatsApp::Crypto::Group::SenderKey
  pair = fixed_group_signing_pair
  chain = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".hexbytes
  WhatsApp::Crypto::Group::SenderKey.new(0x12345678_u32, 0_u32, chain, pair.public_key, pair.private_key)
end

private def verify_with_libsignal(message : Bytes) : JSON::Any
  input = {"crystal_message" => Base64.encode(message)}.to_json
  output = IO::Memory.new
  status = Process.run("/tmp/grp/grp", input: IO::Memory.new(input), output: output)
  raise "libsignal vector harness failed: #{output}" unless status.success?
  JSON.parse(output.to_s)
end

describe WhatsApp::Crypto::Group do
  go_distribution = Base64.decode("Mwj4rNGRARAAGiAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyIhBTWActY2WIDRruoymt+RITg4Ue0hoo47dell0NLNFmJU")
  go_message = Base64.decode("Mwj4rNGRARAAGjD7GMw/O6cRZ2iybalXGV5uVj9ObR4BmT3kPtzT6tZHM+I4RdBspJqmELeelVpL1SF4vRGIfBYytAzWmtPunfOEBZP93EEXJs1WyXlhY09Nf9l0+0p0umQywBep0xTMQjJv5DDhvZvAkdUO1tcAV88D")
  go_unsigned_body = Base64.decode("Mwj4rNGRARAAGjD7GMw/O6cRZ2iybalXGV5uVj9ObR4BmT3kPtzT6tZHM+I4RdBspJqmELeelVpL1SE=")
  plaintext = "libsignal group sender-key vector".to_slice

  it "matches libsignal's deterministic skdm protobuf and version framing" do
    pair = fixed_group_signing_pair
    record = fixed_group_record
    distribution = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.new(
      record.id,
      record.iteration,
      record.chain_key,
      pair.public_key,
    )

    distribution.serialize.should eq(go_distribution)
    decoded = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.deserialize(go_distribution)
    decoded.id.should eq(record.id)
    decoded.iteration.should eq(record.iteration)
    decoded.chain_key.should eq(record.chain_key)
    decoded.signing_public_key.should eq(pair.public_key)
  end

  it "decrypts and verifies a libsignal-produced skmsg" do
    distribution = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.deserialize(go_distribution)
    receiver = WhatsApp::Crypto::Group::SenderKey.from_distribution(distribution)

    WhatsApp::Crypto::Group::GroupCipher.new.decrypt(receiver, go_message).should eq(plaintext)
    receiver.iteration.should eq(1_u32)
  end

  it "produces a Go-identical unsigned body and a message libsignal accepts" do
    record = fixed_group_record
    message = WhatsApp::Crypto::Group::GroupCipher.new.encrypt(record, plaintext)
    parsed = WhatsApp::Crypto::Group::SenderKeyMessage.deserialize(message)

    parsed.unsigned_serialize.should eq(go_unsigned_body)
    record.iteration.should eq(1_u32)
    verify_with_libsignal(message)["decrypted"].as_s.should eq(String.new(plaintext))
  end

  it "restores the sender signing key and chain from serialized state" do
    original = fixed_group_record
    restored = WhatsApp::Crypto::Group::SenderKey.from_serialized(original.serialize)

    restored.id.should eq(original.id)
    restored.iteration.should eq(original.iteration)
    restored.chain_key.should eq(original.chain_key)
    restored.signing_public_key.should eq(original.signing_public_key)
    restored.signing_private_key.should eq(original.signing_private_key)

    message = WhatsApp::Crypto::Group::GroupCipher.new.encrypt(restored, plaintext)
    verify_with_libsignal(message)["decrypted"].as_s.should eq(String.new(plaintext))
  end

  it "persists receiver state and retains skipped message keys" do
    sender = fixed_group_record
    cipher = WhatsApp::Crypto::Group::GroupCipher.new
    first = cipher.encrypt(sender, "first".to_slice)
    second = cipher.encrypt(sender, "second".to_slice)

    distribution = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.deserialize(go_distribution)
    receiver = WhatsApp::Crypto::Group::SenderKey.from_distribution(distribution)
    cipher.decrypt(receiver, second).should eq("second".to_slice)
    receiver.iteration.should eq(2_u32)

    reloaded = WhatsApp::Crypto::Group::SenderKey.from_serialized(receiver.serialize)
    cipher.decrypt(reloaded, first).should eq("first".to_slice)
    reloaded.iteration.should eq(2_u32)
    reloaded.skipped_message_keys.size.should eq(0)
  end

  it "stores and retrieves records by sender-key id" do
    store = WhatsApp::Crypto::Group::InMemorySenderKeyStore.new
    record = fixed_group_record
    store.store(record)

    store.load(record.id).should be(record)
    store.load(99_u32).should be_nil
  end
end

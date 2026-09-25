require "./spec_helper"

# Exercises the adapters that connect the wire layer to the libsignal ports,
# without a socket: sender-key persistence and pairwise session lifecycle.
private def with_database(&)
  path = File.join(Dir.tempdir, "whatsapp-bridge-spec-#{Random::Secure.hex(8)}.db")
  begin
    yield path
  ensure
    File.delete(path) if File.exists?(path)
  end
end

private def with_device(path : String, &)
  session = WhatsApp::Store::Session.new(path)
  begin
    yield WhatsApp::DeviceState.load_or_create(session), session
  ensure
    session.close
  end
end

describe WhatsApp::GroupSenderCrypto do
  it "produces a distribution message a receiver can decrypt with" do
    with_database do |path|
      with_device(path) do |device, session|
        crypto = WhatsApp::GroupSenderCrypto.new(session, device)
        group = "1234567890-1234567890@g.us"

        distribution = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.deserialize(crypto.distribution(group))
        ciphertext = crypto.encrypt(group, "hello group".to_slice)

        receiver = WhatsApp::Crypto::Group::SenderKey.from_distribution(distribution)
        WhatsApp::Crypto::Group::GroupCipher.new.decrypt(receiver, ciphertext).should eq("hello group".to_slice)

        # The sender chain advances, so consecutive messages have distinct keys.
        crypto.encrypt(group, "second".to_slice).should_not eq(ciphertext)
      end
    end
  end

  it "reuses the persisted sender key across clients" do
    with_database do |path|
      group = "9999999999-8888888888@g.us"
      with_device(path) do |device, session|
        first = WhatsApp::GroupSenderCrypto.new(session, device)
        id = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.deserialize(first.distribution(group)).id
        first.encrypt(group, "one".to_slice)

        with_device(path) do |reloaded_device, reloaded_session|
          second = WhatsApp::GroupSenderCrypto.new(reloaded_session, reloaded_device)
          second_id = WhatsApp::Crypto::Group::SenderKeyDistributionMessage.deserialize(second.distribution(group)).id
          second_id.should eq(id)
        end
      end
    end
  end
end

describe WhatsApp::SignalPairwiseCrypto do
  it "establishes a session from a bundle and then reuses it" do
    with_database do |path|
      with_device(path) do |device, _session|
        store = WhatsApp::Crypto::Signal::Store::SQLite.new(path)
        pairwise = WhatsApp::SignalPairwiseCrypto.new(store, device)

        remote_identity = WhatsApp::Crypto::Curve25519KeyPair.generate
        signed_prekey = WhatsApp::Crypto::Curve25519KeyPair.generate
        signature = WhatsApp::Crypto::XEdDSA.sign(
          remote_identity.private_key,
          WhatsApp::PreKey.signature_input(signed_prekey.public_key)
        )
        bundle = WhatsApp::PreKeyBundle.new(
          registration_id: 4242_u32,
          device_id: 1_u32,
          prekey_id: nil,
          prekey_public: nil,
          signed_prekey_id: 7_u32,
          signed_prekey_public: signed_prekey.public_key,
          signed_prekey_signature: signature,
          identity_key: remote_identity.public_key,
        )
        target = "15551234567:1@s.whatsapp.net"

        pairwise.session?(target).should be_false
        type, ciphertext = pairwise.encrypt(target, bundle, "distribution".to_slice)
        type.should eq("pkmsg")
        ciphertext.should_not be_empty
        pairwise.session?(target).should be_true

        # libsignal keeps sending prekey messages until the peer replies, so the
        # second message reuses the session but stays a pkmsg with fresh keys.
        follow_up_type, follow_up = pairwise.encrypt(target, nil, "text".to_slice)
        follow_up_type.should eq("pkmsg")
        follow_up.should_not eq(ciphertext)
      end
    end
  end

  it "refuses to send on an unknown session without a bundle" do
    with_database do |path|
      with_device(path) do |device, _session|
        pairwise = WhatsApp::SignalPairwiseCrypto.new(WhatsApp::Crypto::Signal::Store::SQLite.new(path), device)
        expect_raises(WhatsApp::Error, /no Signal session/) do
          pairwise.encrypt("15550000000:1@s.whatsapp.net", nil, "text".to_slice)
        end
      end
    end
  end
end

require "./spec_helper"
require "../src/whatsapp/crypto/signal/protocol"
require "../src/whatsapp/crypto/signal/ratchet"
require "../src/whatsapp/store/signal_store"
require "../src/whatsapp/crypto/signal/session"

alias SignalStore = WhatsApp::Crypto::Signal::Store
alias SignalSessionBuilder = WhatsApp::Crypto::Signal::SessionBuilder
alias SignalSessionCipher = WhatsApp::Crypto::Signal::SessionCipher
alias SignalAddress = WhatsApp::Crypto::Signal::Address
alias SignalCiphertextMessage = WhatsApp::Crypto::Signal::CiphertextMessage

private def signal_hex(value : String) : Bytes
  bytes = Bytes.new(value.size // 2)
  bytes.size.times do |index|
    bytes[index] = value[index * 2, 2].to_u8(16)
  end
  bytes
end

private def signal_pair(private_key : String, public_key : String) : WhatsApp::Crypto::Curve25519KeyPair
  WhatsApp::Crypto::Curve25519KeyPair.new(signal_hex(private_key), signal_hex(public_key))
end

private def signal_generator(keys : Array(WhatsApp::Crypto::Curve25519KeyPair)) : Proc(WhatsApp::Crypto::Curve25519KeyPair)
  index = 0
  -> {
    key = keys[index]? || raise "deterministic Signal key source exhausted"
    index += 1
    key
  }
end

private def signal_concat(parts : Array(Bytes)) : Bytes
  parts.reduce(Bytes.new(0)) { |result, part| result + part }
end

module SignalVector
  ALICE_IDENTITY = signal_pair(
    "1012131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f70",
    "4d27bcee3135c4944b28d27dd809b07be10c35160d20131caa7e85575498d07c"
  )
  BOB_IDENTITY = signal_pair(
    "4042434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
    "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466"
  )
  BOB_SIGNED = signal_pair(
    "7072737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f50",
    "d214723afdfe2cddbdc929b18a5e43017e44445fc5d6c8fcf88b1868c53f395c"
  )
  BOB_ONE_TIME = signal_pair(
    "9092939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf70",
    "9cced751b301bbd16c4fb8deddd82f18925d71ed90c844fa0158f845b0fa7f4b"
  )
  BASE = signal_pair(
    "0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60",
    "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
  )
  ALICE_RATCHET = signal_pair(
    "2022232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
    "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b"
  )
  BOB_RATCHET = signal_pair(
    "4042434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
    "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466"
  )
  ALICE_RATCHET_2 = signal_pair(
    "6062636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f40",
    "244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49"
  )
  BOB_RATCHET_2 = signal_pair(
    "8082838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f60",
    "883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c77"
  )
  SIGNATURE = signal_hex("18f02a906bcbdd3095db1491e7456b6b4b653d15acdd597c4d58ffef38d50004f859b5786e58f39c8c41613bebbe1f40f806a0872c8573602a28c8231e4c1381")
  BUNDLE    = WhatsApp::Crypto::Signal::PreKeyBundle.new(
    2222_u32, 2_u32, 9_u32, BOB_ONE_TIME.public_key, 7_u32,
    BOB_SIGNED.public_key, SIGNATURE, BOB_IDENTITY.public_key
  )
  GO_MESSAGES = [
    Base64.decode("MwgJEiEFB6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHwaIQVNJ7zuMTXElEso0n3YCbB74Qw1Fg0gExyqfoVXVJjQfCJCMwohBVhpr/RQVJcyy6rtXl35swptoxyw5XQrrVrUoado8aZ7EAAYACIQ1K16trdubUpQcyyppV8wo6r10SkCx6gwKNcIMAc="),
    Base64.decode("MwohBWSxAbHQvlqHBL0Hj5iVAB/APo6flSLxiN0SjZhG1IRmEAAY/////w8iEL9mE/AFAELDqi2YfaIFRBSdUReATEz8AQ=="),
    Base64.decode("MwohBSRP47lj6JndKVuv/OJI01MPOpp0eboGMAJoDr/nra1JEAAYACIQ2kABCVxDOoBpeJblJJIb9zuPVTGWSRQ8"),
    Base64.decode("MwohBSRP47lj6JndKVuv/OJI01MPOpp0eboGMAJoDr/nra1JEAEYACIQMhcvPUJauu55rQZAFsrXfNKMPYrR18Cw"),
  ]
end

describe WhatsApp::Crypto::Signal do
  it "matches libsignal root-step and message-key KDF vectors" do
    root = signal_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    dh = signal_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
    chain = signal_hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
    root_out, root_chain = WhatsApp::Crypto::Signal::Ratchet.root_step(root, dh)
    (root_out + root_chain).should eq(signal_hex("62ffc77945c7aae74572869ac8a9522d96bc75a79cf3863ae7335004186255b32de7be8dc5a58c68bcb5db2e71cb88157ed10ab4f7ea97ba5606e49733da2b94"))

    keys, next_chain = WhatsApp::Crypto::Signal::Ratchet.message_keys(chain)
    signal_concat([keys.cipher_key, keys.mac_key, keys.iv]).should eq(signal_hex("928770c4b574b24829b5bcc03c7c49448018b805586fd9794e8302fcc8cc4963f3988185838ad4902d271bd1335d79a8eae7767478d4a0c3fdfabe3a068f191d7ae3fa7a6dbc847e1fe338c3f85ba504"))
    next_chain.should eq(signal_hex("5d05b0e04b30e26d356c68adb8b501ef077864c403f2939c8c96742f1d65d606"))
  end

  it "matches libsignal ciphertexts across prekey setup, DH ratchet, and out-of-order delivery" do
    bob_store = SignalStore::Memory.new
    bob_store.local_registration_id = 2222_u32
    bob_store.save_local_identity(SignalVector::BOB_IDENTITY)
    bob_store.save_signed_prekey(7_u32, SignalVector::BOB_SIGNED, SignalVector::SIGNATURE)
    bob_store.save_one_time_prekey(9_u32, SignalVector::BOB_ONE_TIME)
    bob_cipher = SignalSessionCipher.new(bob_store, SignalVector::BOB_IDENTITY,
      signal_generator([SignalVector::BOB_RATCHET, SignalVector::BOB_RATCHET_2]))

    alice_store = SignalStore::Memory.new
    alice_store.local_registration_id = 1111_u32
    builder = SignalSessionBuilder.new(alice_store, SignalVector::ALICE_IDENTITY,
      signal_generator([SignalVector::BASE, SignalVector::ALICE_RATCHET]))
    alice_address = SignalAddress.new("bob", 2)
    builder.process_pre_key_bundle(SignalVector::BUNDLE, alice_address)
    alice_cipher = SignalSessionCipher.new(alice_store, SignalVector::ALICE_IDENTITY,
      signal_generator([SignalVector::ALICE_RATCHET_2]))

    outbound = alice_cipher.encrypt(alice_address, "go-first".to_slice)
    outbound.type.should eq(:prekey)
    outbound.serialize.should eq(SignalVector::GO_MESSAGES[0])

    bob_address = SignalAddress.new("alice", 1)
    incoming_first = SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[0])
    incoming_first.type.should eq(:prekey)
    bob_cipher.decrypt(bob_address, incoming_first).should eq("go-first".to_slice)
    bob_store.one_time_prekey(9_u32).should be_nil
    # Alice consumes libsignal's reply, then emits bytes accepted by Go.
    alice_cipher.decrypt(alice_address, SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[1])).should eq("go-reply".to_slice)
    alice_cipher.encrypt(alice_address, "go-second".to_slice).serialize.should eq(SignalVector::GO_MESSAGES[2])

    # The third Go message arrives first; counter zero is retained as a skipped key.
    bob_cipher.decrypt(bob_address, SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[3])).should eq("go-third".to_slice)
    tampered = SignalVector::GO_MESSAGES[2].dup
    tampered[tampered.size - 1] ^= 1_u8
    expect_raises(WhatsApp::Error) do
      bob_cipher.decrypt(bob_address, SignalCiphertextMessage.parse(tampered))
    end
    bob_cipher.decrypt(bob_address, SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[2])).should eq("go-second".to_slice)
    expect_raises(WhatsApp::Error) do
      bob_cipher.decrypt(bob_address, SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[2]))
    end
  end

  it "promotes an archived session when its late reply arrives" do
    store = SignalStore::Memory.new
    store.local_registration_id = 1111_u32
    store.save_local_identity(SignalVector::ALICE_IDENTITY)
    address = SignalAddress.new("bob", 2)
    builder = SignalSessionBuilder.new(store, SignalVector::ALICE_IDENTITY,
      signal_generator([SignalVector::BASE, SignalVector::ALICE_RATCHET]))
    builder.process_pre_key_bundle(SignalVector::BUNDLE, address)
    cipher = SignalSessionCipher.new(store, SignalVector::ALICE_IDENTITY)
    cipher.encrypt(address, "go-first".to_slice).serialize.should eq(SignalVector::GO_MESSAGES[0])

    SignalSessionBuilder.new(store, SignalVector::ALICE_IDENTITY).process_pre_key_bundle(SignalVector::BUNDLE, address)
    replaced = WhatsApp::Crypto::Signal::SessionState.from_bytes(store.session(address).not_nil!)
    replaced.archived_states.size.should eq(1)

    cipher.decrypt(address, SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[1])).should eq("go-reply".to_slice)
    promoted = WhatsApp::Crypto::Signal::SessionState.from_bytes(store.session(address).not_nil!)
    promoted.base_key.should eq(SignalVector::BASE.public_key)
    promoted.archived_states.size.should eq(1)
  end

  it "persists prekeys, identity, ratchet state, and sessions in SQLite" do
    path = File.tempname("signal-session", ".sqlite")
    store = SignalStore::SQLite.new(path)
    store.local_registration_id = 2222_u32
    store.save_local_identity(SignalVector::BOB_IDENTITY)
    store.save_signed_prekey(7_u32, SignalVector::BOB_SIGNED, SignalVector::SIGNATURE)
    store.save_one_time_prekey(9_u32, SignalVector::BOB_ONE_TIME)
    cipher = SignalSessionCipher.new(store, SignalVector::BOB_IDENTITY,
      signal_generator([SignalVector::BOB_RATCHET]))
    alice_address = SignalAddress.new("alice", 1)
    cipher.decrypt(alice_address, SignalCiphertextMessage.parse(SignalVector::GO_MESSAGES[0])).should eq("go-first".to_slice)
    store.close

    reopened = SignalStore::SQLite.new(path)
    reopened.local_registration_id.should eq(2222_u32)
    reopened.local_identity.not_nil!.private_key.should eq(SignalVector::BOB_IDENTITY.private_key)
    reopened.signed_prekey(7_u32).not_nil!.signature.should eq(SignalVector::SIGNATURE)
    reopened.one_time_prekey(9_u32).should be_nil
    resumed_cipher = SignalSessionCipher.new(reopened, SignalVector::BOB_IDENTITY,
      signal_generator([] of WhatsApp::Crypto::Curve25519KeyPair))
    resumed_cipher.encrypt(alice_address, "go-reply".to_slice).serialize.should eq(SignalVector::GO_MESSAGES[1])
    reopened.close
    File.delete(path) if File.exists?(path)
  end
end

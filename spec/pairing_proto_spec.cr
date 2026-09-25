require "./spec_helper"

def protobuf_field_numbers(data : Bytes) : Array(Int32)
  reader = WhatsApp::Proto::Reader.new(data)
  fields = [] of Int32
  reader.each_field do |field, wire_type|
    fields << field
    case wire_type
    when 0
      reader.uint_field
    when 2
      reader.bytes_field
    else
      reader.skip(wire_type)
    end
  end
  fields
end

def protobuf_bytes_field(data : Bytes, target : Int32) : Bytes?
  reader = WhatsApp::Proto::Reader.new(data)
  value = nil.as(Bytes?)
  reader.each_field do |field, wire_type|
    if field == target && wire_type == 2
      value = reader.bytes_field
    else
      reader.skip(wire_type)
    end
  end
  value
end

describe WhatsApp::Proto::Pairing do
  it "extracts the six refs from the captured pair-device IQ" do
    body = File.read(File.join(__DIR__, "fixtures/pair_device_node.hex")).strip.hexbytes
    node = WhatsApp::Binary::Codec.decode(body)

    node.tag.should eq("iq")
    refs = WhatsApp::Proto::Pairing::DeviceRefs.parse(node)
    refs.size.should eq(6)
    refs.each { |ref| ref.should_not be_empty }
  end

  it "round trips web device props using the schema field numbers" do
    props = WhatsApp::Proto::Companion::DeviceProps.web
    encoded = props.encode
    protobuf_field_numbers(encoded).should eq([1, 2, 3, 4, 5])

    version = protobuf_bytes_field(encoded, 2).not_nil!
    protobuf_field_numbers(version).should eq([1, 2, 3])
    history = protobuf_bytes_field(encoded, 5).not_nil!
    protobuf_field_numbers(history).should eq([3, 4, 6, 7, 8, 9, 10, 11, 12, 14, 15, 19, 21, 22])

    decoded = WhatsApp::Proto::Companion::DeviceProps.decode(encoded)
    decoded.os.should eq("whatsapp-crystal")
    decoded.version.not_nil!.primary.should eq(0_u32)
    decoded.version.not_nil!.secondary.should eq(1_u32)
    decoded.version.not_nil!.tertiary.should eq(0_u32)
    decoded.platform_type.should eq(0_u32)
    decoded.require_full_sync.should eq(false)
    decoded.history_sync_config.not_nil!.storage_quota_mb.should eq(10_240_u32)
    decoded.history_sync_config.not_nil!.inline_initial_payload_in_e2ee_msg.should eq(true)
    decoded.encode.should eq(encoded)
  end

  it "round trips ADV signed device identity and its HMAC wrapper" do
    identity = WhatsApp::Proto::ADV::DeviceIdentity.new(123_u64, 456_u64, 7_u32, 1_u32, 0_u32)
    identity_decoded = WhatsApp::Proto::ADV::DeviceIdentity.decode(identity.encode)
    identity_decoded.raw_id.should eq(123_u64)
    identity_decoded.timestamp.should eq(456_u64)
    identity_decoded.key_index.should eq(7_u32)
    identity_decoded.account_type.should eq(1_u32)
    identity_decoded.device_type.should eq(0_u32)

    signed = WhatsApp::Proto::ADV::SignedDeviceIdentity.new(identity.encode, "account-key".to_slice, "account-signature".to_slice, "device-signature".to_slice)
    signed_round_trip = WhatsApp::Proto::ADV::SignedDeviceIdentity.decode(signed.encode)
    signed_round_trip.details.should eq(identity.encode)
    signed_round_trip.account_signature_key.should eq("account-key".to_slice)
    signed_round_trip.account_signature.should eq("account-signature".to_slice)
    signed_round_trip.device_signature.should eq("device-signature".to_slice)

    container = WhatsApp::Proto::ADV::SignedDeviceIdentityHMAC.new(signed.encode, "mac".to_slice, 1_u32)
    container_round_trip = WhatsApp::Proto::ADV::SignedDeviceIdentityHMAC.decode(container.encode)
    container_round_trip.details.should eq(signed.encode)
    container_round_trip.hmac.should eq("mac".to_slice)
    container_round_trip.account_type.should eq(1_u32)
    WhatsApp::Proto::ADV::SignedDeviceIdentity.decode(container_round_trip.details).account_signature_key.should eq("account-key".to_slice)
  end

  it "parses the pair-success node fields and preserves raw client props" do
    props_bytes = WhatsApp::Proto::Companion::ClientPairingProps.new(is_chat_db_lid_migrated: false, is_syncd_pure_lid_session: true).encode
    identity = "signed-identity".to_slice
    success = WhatsApp::Binary::Node.new("pair-success", children: [
      WhatsApp::Binary::Node.new("device-identity", content: identity),
      WhatsApp::Binary::Node.new("biz", attrs: {"name" => "Example Business"}),
      WhatsApp::Binary::Node.new("device", attrs: {"jid" => "123:4@s.whatsapp.net", "lid" => "456:0@lid"}),
      WhatsApp::Binary::Node.new("platform", attrs: {"name" => "web"}),
      WhatsApp::Binary::Node.new("client-props", content: props_bytes),
    ])
    iq = WhatsApp::Binary::Node.new("iq", attrs: {"id" => "PAIR-1"}, children: [success])

    parsed = WhatsApp::Proto::Pairing::Success.parse(iq)
    parsed.request_id.should eq("PAIR-1")
    parsed.device_identity.should eq(identity)
    parsed.business_name.should eq("Example Business")
    parsed.jid.should eq("123:4@s.whatsapp.net")
    parsed.lid.should eq("456:0@lid")
    parsed.platform.should eq("web")
    parsed.client_props.should eq(props_bytes)

    decoded_props = WhatsApp::Proto::Companion::ClientPairingProps.decode(parsed.client_props.not_nil!)
    decoded_props.is_chat_db_lid_migrated.should eq(false)
    decoded_props.is_syncd_pure_lid_session.should eq(true)
  end
end

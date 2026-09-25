require "../binary/node"

module WhatsApp
  module Proto
    module Pairing
      module DeviceRefs
        def self.parse(node : WhatsApp::Binary::Node) : Array(String)
          pair_device = if node.tag == "pair-device"
                          node
                        else
                          node.child("pair-device")
                        end
          raise WhatsApp::Error.new("pair-device node is missing") unless pair_device

          refs = [] of String
          pair_device.children.each do |child|
            next unless child.tag == "ref"
            content = child.content
            raise WhatsApp::Error.new("pair-device ref node has no binary content") unless content
            refs << String.new(content)
          end
          refs
        end
      end

      class Success
        getter request_id : String
        getter device_identity : Bytes
        getter business_name : String?
        getter jid : String?
        getter lid : String?
        getter platform : String?
        getter client_props : Bytes?

        def initialize(@request_id : String, @device_identity : Bytes, @business_name : String? = nil, @jid : String? = nil, @lid : String? = nil, @platform : String? = nil, @client_props : Bytes? = nil)
        end

        # The live server does not always tag the pair-success IQ, so the id is
        # optional; callers echo it when present.
        def self.parse(node : WhatsApp::Binary::Node) : self
          request_id = node.attribute("id") || ""

          pair_success = if node.tag == "pair-success"
                           node
                         else
                           node.child("pair-success")
                         end
          raise WhatsApp::Error.new("pair-success node is missing") unless pair_success

          device_identity_node = pair_success.child("device-identity")
          raise WhatsApp::Error.new("pair-success node is missing device-identity") unless device_identity_node
          device_identity = device_identity_node.content
          raise WhatsApp::Error.new("pair-success device-identity has no binary content") unless device_identity

          business_name = pair_success.child("biz").try(&.attribute("name"))
          device = pair_success.child("device")
          jid = device.try(&.attribute("jid"))
          lid = device.try(&.attribute("lid"))
          platform = pair_success.child("platform").try(&.attribute("name"))
          client_props = pair_success.child("client-props").try(&.content)

          new(request_id, device_identity, business_name, jid, lid, platform, client_props)
        end
      end
    end
  end
end

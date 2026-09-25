module WhatsApp
  module Binary
    alias Attrs = Hash(String, String)

    class Node
      getter tag : String
      getter attrs : Attrs
      getter content : Bytes?
      getter children : Array(Node)

      # attrs and children default to empty so callers can write
      # Node.new("tag", nil, content) for attribute-less nodes.
      def initialize(@tag : String, attrs : Attrs? = nil, @content : Bytes? = nil, @children : Array(Node) = [] of Node)
        @attrs = attrs || Attrs.new
      end

      def child(tag : String) : Node?
        @children.find { |node| node.tag == tag }
      end

      def attribute(name : String) : String?
        @attrs[name]?
      end

      def leaf? : Bool
        @children.empty?
      end
    end
  end
end

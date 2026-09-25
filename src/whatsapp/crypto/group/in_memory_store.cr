require "./sender_key"
require "./sender_key_distribution_message"

module WhatsApp
  module Crypto
    module Group
      # Small keyed store for local/offline clients and crypto specs. Persist a
      # record with SenderKey#serialize; restore it with SenderKey.from_serialized.
      class InMemorySenderKeyStore
        def initialize
          @records = Hash(UInt32, SenderKey).new
        end

        def store(record : SenderKey) : Nil
          @records[record.id] = record
        end

        def load(id : UInt32) : SenderKey?
          @records[id]?
        end

        def process_distribution(message : SenderKeyDistributionMessage) : SenderKey
          record = SenderKey.from_distribution(message)
          store(record)
          record
        end

        def delete(id : UInt32) : Nil
          @records.delete(id)
        end

        def size : Int32
          @records.size
        end
      end
    end
  end
end

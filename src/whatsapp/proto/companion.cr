require "./writer"
require "./handshake"

module WhatsApp
  module Proto
    module Companion
      class AppVersion
        property primary : UInt32?
        property secondary : UInt32?
        property tertiary : UInt32?
        property quaternary : UInt32?
        property quinary : UInt32?

        def initialize(@primary : UInt32? = nil, @secondary : UInt32? = nil, @tertiary : UInt32? = nil, @quaternary : UInt32? = nil, @quinary : UInt32? = nil)
        end

        def encode : Bytes
          writer = Writer.new
          writer.uint(1, @primary.not_nil!.to_u64) if @primary
          writer.uint(2, @secondary.not_nil!.to_u64) if @secondary
          writer.uint(3, @tertiary.not_nil!.to_u64) if @tertiary
          writer.uint(4, @quaternary.not_nil!.to_u64) if @quaternary
          writer.uint(5, @quinary.not_nil!.to_u64) if @quinary
          writer.bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          primary = nil.as(UInt32?)
          secondary = nil.as(UInt32?)
          tertiary = nil.as(UInt32?)
          quaternary = nil.as(UInt32?)
          quinary = nil.as(UInt32?)

          reader.each_field do |field, wire_type|
            if field >= 1 && field <= 5
              raise WhatsApp::Error.new("companion app version field #{field} has invalid wire type") unless wire_type == 0
              value = uint32(reader.uint_field, field)
              case field
              when 1 then primary = value
              when 2 then secondary = value
              when 3 then tertiary = value
              when 4 then quaternary = value
              when 5 then quinary = value
              end
            else
              reader.skip(wire_type)
            end
          end

          new(primary, secondary, tertiary, quaternary, quinary)
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid companion app version protobuf: #{ex.message}")
        end

        private def self.uint32(value : UInt64, field : Int32) : UInt32
          raise WhatsApp::Error.new("companion app version field #{field} exceeds uint32") if value > UInt32::MAX
          value.to_u32
        end
      end

      class HistorySyncConfig
        property full_sync_days_limit : UInt32?
        property full_sync_size_mb_limit : UInt32?
        property storage_quota_mb : UInt32?
        property inline_initial_payload_in_e2ee_msg : Bool?
        property recent_sync_days_limit : UInt32?
        property support_call_log_history : Bool?
        property support_bot_user_agent_chat_history : Bool?
        property support_cag_reactions_and_polls : Bool?
        property support_biz_hosted_msg : Bool?
        property support_recent_sync_chunk_message_count_tuning : Bool?
        property support_hosted_group_msg : Bool?
        property support_fbid_bot_chat_history : Bool?
        property support_add_on_history_sync_migration : Bool?
        property support_message_association : Bool?
        property support_group_history : Bool?
        property on_demand_ready : Bool?
        property support_guest_chat : Bool?
        property complete_on_demand_ready : Bool?
        property thumbnail_sync_days_limit : UInt32?
        property initial_sync_max_messages_per_chat : UInt32?
        property support_manus_history : Bool?
        property support_hatch_history : Bool?
        property supported_bot_channel_fbids : Array(String) = [] of String
        property support_inline_contacts : Bool?

        def encode : Bytes
          writer = Writer.new
          writer.uint(1, @full_sync_days_limit.not_nil!.to_u64) if @full_sync_days_limit
          writer.uint(2, @full_sync_size_mb_limit.not_nil!.to_u64) if @full_sync_size_mb_limit
          writer.uint(3, @storage_quota_mb.not_nil!.to_u64) if @storage_quota_mb
          writer.bool(4, @inline_initial_payload_in_e2ee_msg.not_nil!) unless @inline_initial_payload_in_e2ee_msg.nil?
          writer.uint(5, @recent_sync_days_limit.not_nil!.to_u64) if @recent_sync_days_limit
          writer.bool(6, @support_call_log_history.not_nil!) unless @support_call_log_history.nil?
          writer.bool(7, @support_bot_user_agent_chat_history.not_nil!) unless @support_bot_user_agent_chat_history.nil?
          writer.bool(8, @support_cag_reactions_and_polls.not_nil!) unless @support_cag_reactions_and_polls.nil?
          writer.bool(9, @support_biz_hosted_msg.not_nil!) unless @support_biz_hosted_msg.nil?
          writer.bool(10, @support_recent_sync_chunk_message_count_tuning.not_nil!) unless @support_recent_sync_chunk_message_count_tuning.nil?
          writer.bool(11, @support_hosted_group_msg.not_nil!) unless @support_hosted_group_msg.nil?
          writer.bool(12, @support_fbid_bot_chat_history.not_nil!) unless @support_fbid_bot_chat_history.nil?
          writer.bool(13, @support_add_on_history_sync_migration.not_nil!) unless @support_add_on_history_sync_migration.nil?
          writer.bool(14, @support_message_association.not_nil!) unless @support_message_association.nil?
          writer.bool(15, @support_group_history.not_nil!) unless @support_group_history.nil?
          writer.bool(16, @on_demand_ready.not_nil!) unless @on_demand_ready.nil?
          writer.bool(17, @support_guest_chat.not_nil!) unless @support_guest_chat.nil?
          writer.bool(18, @complete_on_demand_ready.not_nil!) unless @complete_on_demand_ready.nil?
          writer.uint(19, @thumbnail_sync_days_limit.not_nil!.to_u64) if @thumbnail_sync_days_limit
          writer.uint(20, @initial_sync_max_messages_per_chat.not_nil!.to_u64) if @initial_sync_max_messages_per_chat
          writer.bool(21, @support_manus_history.not_nil!) unless @support_manus_history.nil?
          writer.bool(22, @support_hatch_history.not_nil!) unless @support_hatch_history.nil?
          @supported_bot_channel_fbids.each { |fbid| writer.string(23, fbid) }
          writer.bool(24, @support_inline_contacts.not_nil!) unless @support_inline_contacts.nil?
          writer.bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          config = new

          reader.each_field do |field, wire_type|
            case field
            when 1, 2, 3, 5, 19, 20
              raise WhatsApp::Error.new("companion history sync config field #{field} has invalid wire type") unless wire_type == 0
              value = uint32(reader.uint_field, field)
              case field
              when  1 then config.full_sync_days_limit = value
              when  2 then config.full_sync_size_mb_limit = value
              when  3 then config.storage_quota_mb = value
              when  5 then config.recent_sync_days_limit = value
              when 19 then config.thumbnail_sync_days_limit = value
              when 20 then config.initial_sync_max_messages_per_chat = value
              end
            when 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 24
              raise WhatsApp::Error.new("companion history sync config field #{field} has invalid wire type") unless wire_type == 0
              value = reader.uint_field != 0
              case field
              when  4 then config.inline_initial_payload_in_e2ee_msg = value
              when  6 then config.support_call_log_history = value
              when  7 then config.support_bot_user_agent_chat_history = value
              when  8 then config.support_cag_reactions_and_polls = value
              when  9 then config.support_biz_hosted_msg = value
              when 10 then config.support_recent_sync_chunk_message_count_tuning = value
              when 11 then config.support_hosted_group_msg = value
              when 12 then config.support_fbid_bot_chat_history = value
              when 13 then config.support_add_on_history_sync_migration = value
              when 14 then config.support_message_association = value
              when 15 then config.support_group_history = value
              when 16 then config.on_demand_ready = value
              when 17 then config.support_guest_chat = value
              when 18 then config.complete_on_demand_ready = value
              when 21 then config.support_manus_history = value
              when 22 then config.support_hatch_history = value
              when 24 then config.support_inline_contacts = value
              end
            when 23
              raise WhatsApp::Error.new("companion history sync config field 23 has invalid wire type") unless wire_type == 2
              config.supported_bot_channel_fbids << String.new(reader.bytes_field)
            else
              reader.skip(wire_type)
            end
          end

          config
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid companion history sync config protobuf: #{ex.message}")
        end

        private def self.uint32(value : UInt64, field : Int32) : UInt32
          raise WhatsApp::Error.new("companion history sync config field #{field} exceeds uint32") if value > UInt32::MAX
          value.to_u32
        end
      end

      class DeviceProps
        property os : String?
        property version : AppVersion?
        property platform_type : UInt32?
        property require_full_sync : Bool?
        property history_sync_config : HistorySyncConfig?

        def initialize(@os : String? = nil, @version : AppVersion? = nil, @platform_type : UInt32? = nil, @require_full_sync : Bool? = nil, @history_sync_config : HistorySyncConfig? = nil)
        end

        def self.web(os : String = "whatsapp-crystal") : self
          history = HistorySyncConfig.new
          history.storage_quota_mb = 10_240_u32
          history.inline_initial_payload_in_e2ee_msg = true
          history.support_call_log_history = true
          history.support_bot_user_agent_chat_history = true
          history.support_cag_reactions_and_polls = true
          history.support_biz_hosted_msg = true
          history.support_recent_sync_chunk_message_count_tuning = true
          history.support_hosted_group_msg = true
          history.support_fbid_bot_chat_history = true
          history.support_message_association = true
          history.support_group_history = true
          history.thumbnail_sync_days_limit = 60_u32
          history.support_manus_history = true
          history.support_hatch_history = true

          new(os, AppVersion.new(0_u32, 1_u32, 0_u32), 0_u32, false, history)
        end

        def encode : Bytes
          writer = Writer.new
          writer.string(1, @os.not_nil!) if @os
          writer.message(2, @version.not_nil!.encode) if @version
          writer.uint(3, @platform_type.not_nil!.to_u64) if @platform_type
          writer.bool(4, @require_full_sync.not_nil!) unless @require_full_sync.nil?
          writer.message(5, @history_sync_config.not_nil!.encode) if @history_sync_config
          writer.bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          os = nil.as(String?)
          version = nil.as(AppVersion?)
          platform_type = nil.as(UInt32?)
          require_full_sync = nil.as(Bool?)
          history_sync_config = nil.as(HistorySyncConfig?)

          reader.each_field do |field, wire_type|
            case field
            when 1
              raise WhatsApp::Error.new("companion device props field 1 has invalid wire type") unless wire_type == 2
              os = String.new(reader.bytes_field)
            when 2, 5
              raise WhatsApp::Error.new("companion device props field #{field} has invalid wire type") unless wire_type == 2
              value = reader.bytes_field
              if field == 2
                version = AppVersion.decode(value)
              else
                history_sync_config = HistorySyncConfig.decode(value)
              end
            when 3
              raise WhatsApp::Error.new("companion device props field 3 has invalid wire type") unless wire_type == 0
              value = reader.uint_field
              raise WhatsApp::Error.new("companion device props platform type exceeds uint32") if value > UInt32::MAX
              platform_type = value.to_u32
            when 4
              raise WhatsApp::Error.new("companion device props field 4 has invalid wire type") unless wire_type == 0
              require_full_sync = reader.uint_field != 0
            else
              reader.skip(wire_type)
            end
          end

          new(os, version, platform_type, require_full_sync, history_sync_config)
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid companion device props protobuf: #{ex.message}")
        end
      end

      class ClientPairingProps
        property is_chat_db_lid_migrated : Bool?
        property is_syncd_pure_lid_session : Bool?
        property is_syncd_snapshot_recovery_enabled : Bool?
        property is_hs_thumbnail_sync_enabled : Bool?
        property subscription_sync_payload : Bytes?

        def initialize(@is_chat_db_lid_migrated : Bool? = nil, @is_syncd_pure_lid_session : Bool? = nil, @is_syncd_snapshot_recovery_enabled : Bool? = nil, @is_hs_thumbnail_sync_enabled : Bool? = nil, @subscription_sync_payload : Bytes? = nil)
        end

        def encode : Bytes
          writer = Writer.new
          writer.bool(1, @is_chat_db_lid_migrated.not_nil!) unless @is_chat_db_lid_migrated.nil?
          writer.bool(2, @is_syncd_pure_lid_session.not_nil!) unless @is_syncd_pure_lid_session.nil?
          writer.bool(3, @is_syncd_snapshot_recovery_enabled.not_nil!) unless @is_syncd_snapshot_recovery_enabled.nil?
          writer.bool(4, @is_hs_thumbnail_sync_enabled.not_nil!) unless @is_hs_thumbnail_sync_enabled.nil?
          if payload = @subscription_sync_payload
            writer.raw(5, payload) unless payload.empty?
          end
          writer.bytes
        end

        def self.decode(data : Bytes) : self
          reader = Reader.new(data)
          props = new

          reader.each_field do |field, wire_type|
            case field
            when 1, 2, 3, 4
              raise WhatsApp::Error.new("companion client pairing props field #{field} has invalid wire type") unless wire_type == 0
              value = reader.uint_field != 0
              case field
              when 1 then props.is_chat_db_lid_migrated = value
              when 2 then props.is_syncd_pure_lid_session = value
              when 3 then props.is_syncd_snapshot_recovery_enabled = value
              when 4 then props.is_hs_thumbnail_sync_enabled = value
              end
            when 5
              raise WhatsApp::Error.new("companion client pairing props field 5 has invalid wire type") unless wire_type == 2
              props.subscription_sync_payload = reader.bytes_field
            else
              reader.skip(wire_type)
            end
          end

          props
        rescue ex : ArgumentError
          raise WhatsApp::Error.new("invalid companion client pairing props protobuf: #{ex.message}")
        end
      end
    end
  end
end

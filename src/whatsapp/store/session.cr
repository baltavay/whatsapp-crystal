require "json"
require "sqlite3"

module WhatsApp
  module Store
    class Session
      @db : DB::Database
      getter path : String

      def initialize(@path : String)
        @db = DB.open("sqlite3://#{@path}?foreign_keys=on")
        @db.exec <<-SQL
          CREATE TABLE IF NOT EXISTS whatsapp_session (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            state TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        SQL
        @db.exec <<-SQL
          CREATE TABLE IF NOT EXISTS whatsapp_sender_keys (
            group_jid TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            state BLOB NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_jid, sender_id)
          )
        SQL
        @db.exec <<-SQL
          CREATE TABLE IF NOT EXISTS whatsapp_signal_sender_keys (
            group_jid TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            distribution BLOB NOT NULL,
            secret BLOB NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_jid, sender_id)
          )
        SQL
      end

      def read : JSON::Any?
        raw = @db.query_one?("SELECT state FROM whatsapp_session WHERE id = 1", as: String)
        raw ? JSON.parse(raw) : nil
      end

      def write(state : JSON::Any | String | Hash(String, JSON::Any)) : Nil
        serialized = state.is_a?(String) ? state : state.to_json
        @db.exec(
          "INSERT INTO whatsapp_session (id, state) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET state = excluded.state, updated_at = CURRENT_TIMESTAMP",
          serialized
        )
      end

      def sender_key(group_jid : String, sender_id : String) : Bytes?
        value = @db.query_one?("SELECT state FROM whatsapp_sender_keys WHERE group_jid = ? AND sender_id = ?", group_jid, sender_id, as: Bytes)
        value.try(&.dup)
      end

      def write_sender_key(group_jid : String, sender_id : String, state : Bytes) : Nil
        @db.exec(
          "INSERT INTO whatsapp_sender_keys (group_jid, sender_id, state) VALUES (?, ?, ?) ON CONFLICT(group_jid, sender_id) DO UPDATE SET state = excluded.state, updated_at = CURRENT_TIMESTAMP",
          group_jid, sender_id, state
        )
      end

      def signal_distribution(group_jid : String, sender_id : String) : Bytes?
        value = @db.query_one?("SELECT distribution FROM whatsapp_signal_sender_keys WHERE group_jid = ? AND sender_id = ?", group_jid, sender_id, as: Bytes)
        value.try(&.dup)
      end

      def signal_secret(group_jid : String, sender_id : String) : Bytes?
        value = @db.query_one?("SELECT secret FROM whatsapp_signal_sender_keys WHERE group_jid = ? AND sender_id = ?", group_jid, sender_id, as: Bytes)
        value.try(&.dup)
      end

      def write_signal_sender_key(group_jid : String, sender_id : String, distribution : Bytes, secret : Bytes) : Nil
        @db.exec(
          "INSERT INTO whatsapp_signal_sender_keys (group_jid, sender_id, distribution, secret) VALUES (?, ?, ?, ?) ON CONFLICT(group_jid, sender_id) DO UPDATE SET distribution = excluded.distribution, secret = excluded.secret, updated_at = CURRENT_TIMESTAMP",
          group_jid, sender_id, distribution, secret
        )
      end

      def close : Nil
        @db.close
      end
    end
  end
end

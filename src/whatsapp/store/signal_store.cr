require "sqlite3"
require "base64"
require "../crypto/curve25519"

module WhatsApp
  module Crypto
    module Signal
      module Store
        struct SignedPreKey
          getter key_pair : WhatsApp::Crypto::Curve25519KeyPair
          getter signature : Bytes

          def initialize(@key_pair : WhatsApp::Crypto::Curve25519KeyPair, signature : Bytes)
            @signature = signature.dup
          end
        end

        # Store interface shared by the in-memory and SQLite backends.
        abstract class Base
          abstract def session(address : Address) : Bytes?
          abstract def save_session(address : Address, state : Bytes) : Nil
          abstract def identity(address : Address) : Bytes?
          abstract def save_identity(address : Address, public_key : Bytes) : Nil
          abstract def one_time_prekey(id : UInt32) : WhatsApp::Crypto::Curve25519KeyPair?
          abstract def save_one_time_prekey(id : UInt32, key_pair : WhatsApp::Crypto::Curve25519KeyPair) : Nil
          abstract def remove_one_time_prekey(id : UInt32) : Nil
          abstract def signed_prekey(id : UInt32) : SignedPreKey?
          abstract def save_signed_prekey(id : UInt32, key_pair : WhatsApp::Crypto::Curve25519KeyPair, signature : Bytes) : Nil
          abstract def local_registration_id : UInt32
          abstract def local_registration_id=(value : UInt32) : UInt32
          abstract def save_local_identity(key_pair : WhatsApp::Crypto::Curve25519KeyPair) : Nil
          abstract def local_identity : WhatsApp::Crypto::Curve25519KeyPair?
        end

        class Memory < Base
          @sessions = Hash(String, Bytes).new
          @identities = Hash(String, Bytes).new
          @one_time_prekeys = Hash(UInt32, WhatsApp::Crypto::Curve25519KeyPair).new
          @signed_prekeys = Hash(UInt32, SignedPreKey).new
          @local_identity : WhatsApp::Crypto::Curve25519KeyPair?
          @registration_id = 1_u32

          def session(address : Address) : Bytes?
            @sessions[address.key]?.try(&.dup)
          end

          def save_session(address : Address, state : Bytes) : Nil
            @sessions[address.key] = state.dup
          end

          def identity(address : Address) : Bytes?
            @identities[address.key]?.try(&.dup)
          end

          def save_identity(address : Address, public_key : Bytes) : Nil
            @identities[address.key] = public_key.dup
          end

          def one_time_prekey(id : UInt32) : WhatsApp::Crypto::Curve25519KeyPair?
            @one_time_prekeys[id]?
          end

          def save_one_time_prekey(id : UInt32, key_pair : WhatsApp::Crypto::Curve25519KeyPair) : Nil
            @one_time_prekeys[id] = key_pair
          end

          def remove_one_time_prekey(id : UInt32) : Nil
            @one_time_prekeys.delete(id)
          end

          def signed_prekey(id : UInt32) : SignedPreKey?
            @signed_prekeys[id]?
          end

          def save_signed_prekey(id : UInt32, key_pair : WhatsApp::Crypto::Curve25519KeyPair, signature : Bytes) : Nil
            @signed_prekeys[id] = SignedPreKey.new(key_pair, signature)
          end

          def local_registration_id : UInt32
            @registration_id
          end

          def local_registration_id=(value : UInt32) : UInt32
            @registration_id = value
          end

          def save_local_identity(key_pair : WhatsApp::Crypto::Curve25519KeyPair) : Nil
            @local_identity = key_pair
          end

          def local_identity : WhatsApp::Crypto::Curve25519KeyPair?
            @local_identity
          end
        end

        class SQLite < Base
          getter path : String
          @db : DB::Database

          def initialize(@path : String)
            @db = DB.open("sqlite3://#{@path}?foreign_keys=on")
            @db.exec <<-SQL
              CREATE TABLE IF NOT EXISTS whatsapp_signal_sessions (
                address TEXT PRIMARY KEY NOT NULL,
                state BLOB NOT NULL
              )
            SQL
            @db.exec <<-SQL
              CREATE TABLE IF NOT EXISTS whatsapp_signal_one_time_prekeys (
                id INTEGER PRIMARY KEY NOT NULL,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL
              )
            SQL
            @db.exec <<-SQL
              CREATE TABLE IF NOT EXISTS whatsapp_signal_signed_prekeys (
                id INTEGER PRIMARY KEY NOT NULL,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                signature BLOB NOT NULL
              )
            SQL
            @db.exec <<-SQL
              CREATE TABLE IF NOT EXISTS whatsapp_signal_identities (
                address TEXT PRIMARY KEY NOT NULL,
                public_key BLOB NOT NULL
              )
            SQL
            @db.exec <<-SQL
              CREATE TABLE IF NOT EXISTS whatsapp_signal_local_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                registration_id INTEGER NOT NULL
              )
            SQL
          end

          def session(address : Address) : Bytes?
            @db.query_one?("SELECT state FROM whatsapp_signal_sessions WHERE address = ?", address.key, as: Bytes).try(&.dup)
          end

          def save_session(address : Address, state : Bytes) : Nil
            @db.exec("INSERT INTO whatsapp_signal_sessions(address, state) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET state = excluded.state", address.key, state)
          end

          def identity(address : Address) : Bytes?
            @db.query_one?("SELECT public_key FROM whatsapp_signal_identities WHERE address = ?", address.key, as: Bytes).try(&.dup)
          end

          def save_identity(address : Address, public_key : Bytes) : Nil
            @db.exec("INSERT INTO whatsapp_signal_identities(address, public_key) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET public_key = excluded.public_key", address.key, public_key)
          end

          def one_time_prekey(id : UInt32) : WhatsApp::Crypto::Curve25519KeyPair?
            raw = @db.query_one?("SELECT private_key, public_key FROM whatsapp_signal_one_time_prekeys WHERE id = ?", id, as: {Bytes, Bytes})
            raw.try { |keys| WhatsApp::Crypto::Curve25519KeyPair.new(keys[0].dup, keys[1].dup) }
          end

          def save_one_time_prekey(id : UInt32, key_pair : WhatsApp::Crypto::Curve25519KeyPair) : Nil
            @db.exec("INSERT INTO whatsapp_signal_one_time_prekeys(id, private_key, public_key) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET private_key = excluded.private_key, public_key = excluded.public_key", id, key_pair.private_key, key_pair.public_key)
          end

          def remove_one_time_prekey(id : UInt32) : Nil
            @db.exec("DELETE FROM whatsapp_signal_one_time_prekeys WHERE id = ?", id)
          end

          def signed_prekey(id : UInt32) : SignedPreKey?
            raw = @db.query_one?("SELECT private_key, public_key, signature FROM whatsapp_signal_signed_prekeys WHERE id = ?", id, as: {Bytes, Bytes, Bytes})
            raw.try { |keys| SignedPreKey.new(WhatsApp::Crypto::Curve25519KeyPair.new(keys[0].dup, keys[1].dup), keys[2].dup) }
          end

          def save_signed_prekey(id : UInt32, key_pair : WhatsApp::Crypto::Curve25519KeyPair, signature : Bytes) : Nil
            @db.exec("INSERT INTO whatsapp_signal_signed_prekeys(id, private_key, public_key, signature) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET private_key = excluded.private_key, public_key = excluded.public_key, signature = excluded.signature", id, key_pair.private_key, key_pair.public_key, signature)
          end

          def local_registration_id : UInt32
            @db.query_one?("SELECT registration_id FROM whatsapp_signal_local_identity WHERE id = 1", as: Int64).try(&.to_u32) || 1_u32
          end

          def local_registration_id=(value : UInt32) : UInt32
            if identity = local_identity
              @db.exec("INSERT INTO whatsapp_signal_local_identity(id, private_key, public_key, registration_id) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET registration_id = excluded.registration_id", identity.private_key, identity.public_key, value)
            else
              @db.exec("INSERT INTO whatsapp_signal_local_identity(id, private_key, public_key, registration_id) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET registration_id = excluded.registration_id", Bytes.new(32), Bytes.new(32), value)
            end
            value
          end

          def save_local_identity(key_pair : WhatsApp::Crypto::Curve25519KeyPair) : Nil
            @db.exec("INSERT INTO whatsapp_signal_local_identity(id, private_key, public_key, registration_id) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET private_key = excluded.private_key, public_key = excluded.public_key", key_pair.private_key, key_pair.public_key, local_registration_id)
          end

          def local_identity : WhatsApp::Crypto::Curve25519KeyPair?
            raw = @db.query_one?("SELECT private_key, public_key FROM whatsapp_signal_local_identity WHERE id = 1", as: {Bytes, Bytes})
            raw.try { |keys| WhatsApp::Crypto::Curve25519KeyPair.new(keys[0].dup, keys[1].dup) }
          end

          def close : Nil
            @db.close
          end
        end
      end
    end
  end
end

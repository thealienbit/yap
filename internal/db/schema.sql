PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS entries (
  id TEXT PRIMARY KEY, -- UUID plain text
  -- encrypted fields
  title BLOB NOT NULL,
  username BLOB,
  password BLOB NOT NULL,
  url BLOB,
  notes BLOB,
  -- unix epoch
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  entry_key BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_updated_at 
ON entries(updated_at)

CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  name BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO meta (key, value) VALUES 
  ('schema_version', '1'),
  ('last_migration', '0')

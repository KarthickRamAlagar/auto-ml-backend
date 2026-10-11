-- Auto ML: system of record on Cloudflare D1.
-- Times are Unix seconds (REAL) to match the Python engine. JSON columns hold engine documents verbatim.
-- Datasets are NEVER stored here; uploaded files live in R2 and are tracked in `files`.

CREATE TABLE users (
  id             TEXT PRIMARY KEY,
  username       TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 30),
  email          TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(email) <= 254),
  contact        TEXT CHECK (contact IS NULL OR length(contact) BETWEEN 7 AND 20),
  password_hash  TEXT,                         -- NULL for accounts that only use Google
  google_sub     TEXT UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  -- usage window (the engine's per-account counters; see backend/app/limits.py)
  window_start   REAL,
  free_used      INTEGER NOT NULL DEFAULT 0 CHECK (free_used >= 0),
  paid_used      INTEGER NOT NULL DEFAULT 0 CHECK (paid_used >= 0),
  verified_spend REAL    NOT NULL DEFAULT 0 CHECK (verified_spend >= 0),
  reports_used   INTEGER NOT NULL DEFAULT 0 CHECK (reports_used >= 0),
  paid_blocked   INTEGER NOT NULL DEFAULT 0 CHECK (paid_blocked IN (0, 1)),
  extra          TEXT NOT NULL DEFAULT '{}',   -- any other engine field, kept verbatim
  created_at     REAL NOT NULL,
  updated_at     REAL NOT NULL,
  last_login_at  REAL
);

-- Refresh sessions. Only a SHA-256 of the secret is stored; rotation keeps the previous hash for a short grace
-- window (two tabs refreshing at once) and a replay after that revokes the whole session.
CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL,
  prev_hash    TEXT,
  rotated_at   REAL,
  created_at   REAL NOT NULL,
  last_used_at REAL NOT NULL,
  expires_at   REAL NOT NULL,
  revoked_at   REAL,
  ip           TEXT,
  user_agent   TEXT
);
CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

-- One-time e-mail verification and password-reset links (hash only).
CREATE TABLE auth_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  kind       TEXT NOT NULL CHECK (kind IN ('verify', 'reset')),
  token_hash TEXT NOT NULL UNIQUE,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  used_at    REAL
);
CREATE INDEX idx_auth_tokens_user ON auth_tokens (user_id, kind);
CREATE INDEX idx_auth_tokens_expires ON auth_tokens (expires_at);

-- Payments. `status` is the engine's workflow (created -> claimed -> approved | rejected);
-- `state` is the simple view: pending (created, claimed), completed (approved) or rejected.
CREATE TABLE payments (
  id          TEXT PRIMARY KEY,
  ref         TEXT NOT NULL UNIQUE,
  user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  user_email  TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('models', 'report')),
  job_id      TEXT,
  project_id  TEXT,
  amount      REAL NOT NULL CHECK (amount >= 0),
  currency    TEXT NOT NULL DEFAULT 'INR',
  breakdown   TEXT NOT NULL DEFAULT '{}',
  status      TEXT NOT NULL DEFAULT 'created' CHECK (status IN ('created', 'claimed', 'approved', 'rejected')),
  state       TEXT GENERATED ALWAYS AS (
                CASE status WHEN 'approved' THEN 'completed' WHEN 'rejected' THEN 'rejected' ELSE 'pending' END
              ) VIRTUAL,
  created_at  REAL NOT NULL,
  claimed_at  REAL,
  decided_at  REAL,
  decided_by  TEXT,
  reminded_at REAL,
  reminders   INTEGER NOT NULL DEFAULT 0,
  context     TEXT NOT NULL DEFAULT '{}',
  extra       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_payments_user ON payments (user_id, created_at DESC);
CREATE INDEX idx_payments_status ON payments (status, created_at DESC);
CREATE INDEX idx_payments_job ON payments (user_id, job_id, kind);

-- Chats (the engine calls them projects) and the folders that group them (the engine calls those groups).
CREATE TABLE projects (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  group_id   TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  data       TEXT NOT NULL
);
CREATE INDEX idx_projects_user ON projects (user_id, created_at DESC);
CREATE INDEX idx_projects_updated ON projects (updated_at);

CREATE TABLE groups (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at REAL NOT NULL,
  data       TEXT NOT NULL
);
CREATE INDEX idx_groups_user ON groups (user_id, created_at DESC);

-- Run archives live in R2 (archives/<job_id>.json.gz); this is only the index.
CREATE TABLE archives (
  job_id     TEXT PRIMARY KEY,
  user_id    TEXT,
  r2_key     TEXT NOT NULL,
  size       INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE INDEX idx_archives_user ON archives (user_id);

-- Files users upload (R2). Bytes are in R2 under `r2_key`; rows expire with the retention window.
CREATE TABLE files (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  r2_key     TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  mime       TEXT NOT NULL,
  size       INTEGER NOT NULL CHECK (size >= 0),
  sha256     TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL
);
CREATE INDEX idx_files_user ON files (user_id, created_at DESC);
CREATE INDEX idx_files_expires ON files (expires_at);

CREATE TABLE events (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ts   REAL NOT NULL,
  uid  TEXT,
  data TEXT NOT NULL
);
CREATE INDEX idx_events_ts ON events (ts);

CREATE TABLE vip (
  email    TEXT PRIMARY KEY COLLATE NOCASE,
  added_at REAL NOT NULL
);

CREATE TABLE feedback (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ts   REAL NOT NULL,
  uid  TEXT,
  data TEXT NOT NULL
);
CREATE INDEX idx_feedback_ts ON feedback (ts DESC);

-- Security trail: sign-ins, resets, payment decisions, admin changes.
CREATE TABLE audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      REAL NOT NULL,
  actor   TEXT,
  action  TEXT NOT NULL,
  target  TEXT,
  ip      TEXT,
  detail  TEXT
);
CREATE INDEX idx_audit_ts ON audit_log (ts DESC);
CREATE INDEX idx_audit_actor ON audit_log (actor, ts DESC);

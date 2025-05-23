CREATE TABLE IF NOT EXISTS users
(
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL,
    phone     TEXT NOT NULL UNIQUE,
    pass_hash BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_phone ON users (phone);

CREATE TABLE IF NOT EXISTS apps
(
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE
);
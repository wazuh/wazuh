CREATE TABLE IF NOT EXISTS agent (
    id INTEGER PRIMARY KEY,
    name TEXT,
    ip TEXT,
    key TEXT,
    os TEXT,
    version TEXT,
    date_add NUMERIC DEFAULT CURRENT_TIMESTAMP,
    enabled INTEGER DEFAULT 1
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);
INSERT INTO agent (id) VALUES (0);

CREATE TABLE IF NOT EXISTS fim_file (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_agent INTEGER NOT NULL REFERENCES agent (id),
    path TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry'))
);

CREATE UNIQUE INDEX IF NOT EXISTS fim_file_path ON fim_file (id_agent, path);

CREATE TABLE IF NOT EXISTS fim_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_file INTEGER NOT NULL REFERENCES fim_file (id),
    event TEXT NOT NULL CHECK (event IN ('added', 'modified', 'readded', 'deleted')),
    date NUMERIC,
    size INTEGER,
    perm INTEGER,
    uid INTEGER,
    gid INTEGER,
    md5 TEXT,
    sha1 TEXT
);

CREATE TABLE IF NOT EXISTS pm_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_agent INTEGER NOT NULL REFERENCES agent (id),
    date_first NUMERIC,
    date_last NUMERIC,
    log TEXT
);

CREATE INDEX IF NOT EXISTS pm_event_log ON pm_event (id_agent, log);

PRAGMA journal_mode=WAL;

-- ProcessSentinel SQLite schema (also created automatically by the C++ program)

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    name TEXT NOT NULL,
    parent_name TEXT,
    exe_path TEXT,
    cpu_percent REAL,
    memory_mb REAL,
    num_threads INTEGER,
    num_connections INTEGER,
    io_operations INTEGER,
    child_count INTEGER,
    captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    process_name TEXT PRIMARY KEY,
    avg_cpu REAL,
    avg_memory REAL,
    avg_threads REAL,
    avg_connections REAL,
    avg_io REAL,
    avg_children REAL,
    sample_count INTEGER,
    usual_parents TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER,
    process_name TEXT,
    suspicion_score REAL,
    score_b REAL,
    score_p REAL,
    score_n REAL,
    score_r REAL,
    reasons TEXT,
    captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER,
    process_name TEXT,
    event_type TEXT,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_name ON snapshots(name);
CREATE INDEX IF NOT EXISTS idx_snapshots_time ON snapshots(captured_at);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(suspicion_score);

CREATE VIEW IF NOT EXISTS latest_processes AS
SELECT s.*
FROM snapshots s
INNER JOIN (
    SELECT pid, MAX(captured_at) AS latest_time
    FROM snapshots
    GROUP BY pid
) t ON s.pid = t.pid AND s.captured_at = t.latest_time;

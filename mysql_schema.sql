CREATE DATABASE IF NOT EXISTS process_sentinel;
USE process_sentinel;

CREATE TABLE IF NOT EXISTS snapshots (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pid INT NOT NULL,
    ppid INT,
    name VARCHAR(255) NOT NULL,
    parent_name VARCHAR(255),
    exe_path VARCHAR(500),
    cpu_percent FLOAT,
    memory_mb FLOAT,
    num_threads INT,
    num_connections INT,
    io_operations BIGINT,
    child_count INT,
    captured_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    process_name VARCHAR(255) PRIMARY KEY,
    avg_cpu FLOAT,
    avg_memory FLOAT,
    avg_threads FLOAT,
    avg_connections FLOAT,
    avg_io FLOAT,
    avg_children FLOAT,
    sample_count INT,
    usual_parents TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pid INT,
    process_name VARCHAR(255),
    suspicion_score FLOAT,
    score_b FLOAT,
    score_p FLOAT,
    score_n FLOAT,
    score_r FLOAT,
    reasons TEXT,
    captured_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pid INT,
    process_name VARCHAR(255),
    event_type VARCHAR(100),
    details TEXT,
    created_at DATETIME NOT NULL
);

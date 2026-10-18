-- Extra SQL for DBMS viva. Open sentinel.db in DB Browser for SQLite.

-- 1. Highest alerts
SELECT process_name, pid, suspicion_score, reasons, captured_at
FROM alerts
ORDER BY suspicion_score DESC
LIMIT 20;

-- 2. Average CPU and memory by process name
SELECT name,
       ROUND(AVG(cpu_percent), 2) AS avg_cpu,
       ROUND(AVG(memory_mb), 2) AS avg_memory_mb,
       COUNT(*) AS samples
FROM snapshots
GROUP BY name
ORDER BY avg_cpu DESC;

-- 3. Parent-child pairs
SELECT parent_name, name AS child_name, COUNT(*) AS times_seen
FROM snapshots
WHERE parent_name IS NOT NULL
GROUP BY parent_name, name
ORDER BY times_seen DESC;

-- 4. History compared with baseline
SELECT s.name, s.cpu_percent, b.avg_cpu, s.memory_mb, b.avg_memory, s.captured_at
FROM snapshots s
LEFT JOIN baselines b ON s.name = b.process_name
ORDER BY s.captured_at DESC
LIMIT 50;

-- 5. Use the view
SELECT pid, name, cpu_percent, memory_mb, captured_at
FROM latest_processes
ORDER BY cpu_percent DESC;

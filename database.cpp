#include "database.h"
#include "sqlite3.h"
#include "process_monitor.h"

#include <iostream>
#include <sstream>

using namespace std;

static sqlite3* db = NULL;

static const char* SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS snapshots ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " pid INTEGER NOT NULL,"
    " ppid INTEGER,"
    " name TEXT NOT NULL,"
    " parent_name TEXT,"
    " exe_path TEXT,"
    " cpu_percent REAL,"
    " memory_mb REAL,"
    " num_threads INTEGER,"
    " num_connections INTEGER,"
    " io_operations INTEGER,"
    " child_count INTEGER,"
    " captured_at TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS baselines ("
    " process_name TEXT PRIMARY KEY,"
    " avg_cpu REAL,"
    " avg_memory REAL,"
    " avg_threads REAL,"
    " avg_connections REAL,"
    " avg_io REAL,"
    " avg_children REAL,"
    " sample_count INTEGER,"
    " usual_parents TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS alerts ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " pid INTEGER,"
    " process_name TEXT,"
    " suspicion_score REAL,"
    " score_b REAL,"
    " score_p REAL,"
    " score_n REAL,"
    " score_r REAL,"
    " reasons TEXT,"
    " captured_at TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS events ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " pid INTEGER,"
    " process_name TEXT,"
    " event_type TEXT,"
    " details TEXT,"
    " created_at TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_snapshots_name ON snapshots(name);"
    "CREATE INDEX IF NOT EXISTS idx_snapshots_time ON snapshots(captured_at);"
    "CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(suspicion_score);"
    "CREATE VIEW IF NOT EXISTS latest_processes AS "
    "SELECT s.* FROM snapshots s INNER JOIN ("
    " SELECT pid, MAX(captured_at) AS latest_time FROM snapshots GROUP BY pid"
    ") t ON s.pid = t.pid AND s.captured_at = t.latest_time;";

bool initDatabase() {
    string path = getExeFolder() + "\\sentinel.db";
    int rc = sqlite3_open(path.c_str(), &db);
    if (rc != SQLITE_OK) {
        cout << "Could not open database: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    char* err = NULL;
    rc = sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        cout << "Could not create tables: " << err << endl;
        sqlite3_free(err);
        return false;
    }
    return true;
}

void closeDatabase() {
    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
    }
}

void saveSnapshot(const ProcessInfo& proc) {
    const char* sql =
        "INSERT INTO snapshots (pid, ppid, name, parent_name, exe_path, "
        "cpu_percent, memory_mb, num_threads, num_connections, io_operations, "
        "child_count, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, proc.pid);
    sqlite3_bind_int(stmt, 2, proc.ppid);
    sqlite3_bind_text(stmt, 3, proc.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, proc.parentName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, proc.exePath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 6, proc.cpuPercent);
    sqlite3_bind_double(stmt, 7, proc.memoryMB);
    sqlite3_bind_int(stmt, 8, proc.numThreads);
    sqlite3_bind_int(stmt, 9, proc.numConnections);
    sqlite3_bind_int64(stmt, 10, proc.ioOperations);
    sqlite3_bind_int(stmt, 11, proc.childCount);
    sqlite3_bind_text(stmt, 12, proc.capturedAt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

Baseline getBaseline(const string& processName) {
    Baseline base;
    base.processName = processName;
    base.found = false;
    base.avgCpu = 0;
    base.avgMemory = 0;
    base.avgThreads = 0;
    base.avgConnections = 0;
    base.avgIo = 0;
    base.avgChildren = 0;
    base.sampleCount = 0;
    base.usualParents = "";

    const char* sql = "SELECT * FROM baselines WHERE process_name = ?;";
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, processName.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        base.found = true;
        base.avgCpu = sqlite3_column_double(stmt, 1);
        base.avgMemory = sqlite3_column_double(stmt, 2);
        base.avgThreads = sqlite3_column_double(stmt, 3);
        base.avgConnections = sqlite3_column_double(stmt, 4);
        base.avgIo = sqlite3_column_double(stmt, 5);
        base.avgChildren = sqlite3_column_double(stmt, 6);
        base.sampleCount = sqlite3_column_int(stmt, 7);
        const unsigned char* parents = sqlite3_column_text(stmt, 8);
        if (parents != NULL) {
            base.usualParents = (const char*)parents;
        }
    }
    sqlite3_finalize(stmt);
    return base;
}

void updateBaseline(const ProcessInfo& proc) {
    Baseline old = getBaseline(proc.name);

    if (!old.found) {
        const char* sql =
            "INSERT INTO baselines (process_name, avg_cpu, avg_memory, avg_threads, "
            "avg_connections, avg_io, avg_children, sample_count, usual_parents) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?);";
        sqlite3_stmt* stmt = NULL;
        sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, proc.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 2, proc.cpuPercent);
        sqlite3_bind_double(stmt, 3, proc.memoryMB);
        sqlite3_bind_double(stmt, 4, proc.numThreads);
        sqlite3_bind_double(stmt, 5, proc.numConnections);
        sqlite3_bind_double(stmt, 6, (double)proc.ioOperations);
        sqlite3_bind_double(stmt, 7, proc.childCount);
        sqlite3_bind_text(stmt, 8, proc.parentName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return;
    }

    int n = old.sampleCount;
    string parents = old.usualParents;
    if (!proc.parentName.empty() && parents.find(proc.parentName) == string::npos) {
        if (parents.empty()) {
            parents = proc.parentName;
        } else {
            parents = parents + "," + proc.parentName;
        }
    }

    const char* sql =
        "UPDATE baselines SET avg_cpu=?, avg_memory=?, avg_threads=?, "
        "avg_connections=?, avg_io=?, avg_children=?, sample_count=?, "
        "usual_parents=? WHERE process_name=?;";
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_double(stmt, 1, (old.avgCpu * n + proc.cpuPercent) / (n + 1));
    sqlite3_bind_double(stmt, 2, (old.avgMemory * n + proc.memoryMB) / (n + 1));
    sqlite3_bind_double(stmt, 3, (old.avgThreads * n + proc.numThreads) / (n + 1));
    sqlite3_bind_double(stmt, 4, (old.avgConnections * n + proc.numConnections) / (n + 1));
    sqlite3_bind_double(stmt, 5, (old.avgIo * n + (double)proc.ioOperations) / (n + 1));
    sqlite3_bind_double(stmt, 6, (old.avgChildren * n + proc.childCount) / (n + 1));
    sqlite3_bind_int(stmt, 7, n + 1);
    sqlite3_bind_text(stmt, 8, parents.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, proc.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void saveAlert(const ScoreResult& result, const string& capturedAt) {
    const char* sql =
        "INSERT INTO alerts (pid, process_name, suspicion_score, score_b, score_p, "
        "score_n, score_r, reasons, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, result.pid);
    sqlite3_bind_text(stmt, 2, result.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 3, result.score);
    sqlite3_bind_double(stmt, 4, result.scoreB);
    sqlite3_bind_double(stmt, 5, result.scoreP);
    sqlite3_bind_double(stmt, 6, result.scoreN);
    sqlite3_bind_double(stmt, 7, result.scoreR);
    sqlite3_bind_text(stmt, 8, result.reasons.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, capturedAt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void saveEvent(int pid, const string& name, const string& type, const string& details) {
    const char* sql =
        "INSERT INTO events (pid, process_name, event_type, details, created_at) "
        "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, pid);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, details.c_str(), -1, SQLITE_TRANSIENT);
    string now = currentTimeText();
    sqlite3_bind_text(stmt, 5, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

vector<AlertRow> getRecentAlerts(int limit) {
    vector<AlertRow> rows;
    const char* sql =
        "SELECT pid, process_name, suspicion_score, score_b, score_p, score_n, "
        "score_r, reasons, captured_at FROM alerts "
        "ORDER BY captured_at DESC, suspicion_score DESC LIMIT ?;";
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AlertRow row;
        row.pid = sqlite3_column_int(stmt, 0);
        row.name = (const char*)sqlite3_column_text(stmt, 1);
        row.score = sqlite3_column_double(stmt, 2);
        row.scoreB = sqlite3_column_double(stmt, 3);
        row.scoreP = sqlite3_column_double(stmt, 4);
        row.scoreN = sqlite3_column_double(stmt, 5);
        row.scoreR = sqlite3_column_double(stmt, 6);
        const unsigned char* reasons = sqlite3_column_text(stmt, 7);
        row.reasons = reasons ? (const char*)reasons : "";
        const unsigned char* timeText = sqlite3_column_text(stmt, 8);
        row.capturedAt = timeText ? (const char*)timeText : "";
        rows.push_back(row);
    }
    sqlite3_finalize(stmt);
    return rows;
}

static int countTable(const char* sql) {
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    int value = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        value = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return value;
}

int countSnapshots() {
    return countTable("SELECT COUNT(*) FROM snapshots;");
}

int countAlerts() {
    return countTable("SELECT COUNT(*) FROM alerts;");
}

int countBaselines() {
    return countTable("SELECT COUNT(*) FROM baselines;");
}

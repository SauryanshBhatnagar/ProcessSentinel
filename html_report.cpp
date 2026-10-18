#include "html_report.h"
#include "database.h"
#include "process_monitor.h"

#include <windows.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

using namespace std;

static bool compareScore(const ScoredProcess& a, const ScoredProcess& b);

static string htmlEscape(const string& text) {
    string out;
    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] == '<') out += "&lt;";
        else if (text[i] == '>') out += "&gt;";
        else if (text[i] == '&') out += "&amp;";
        else out += text[i];
    }
    return out;
}

static string levelText(double score) {
    if (score >= 75) return "High";
    if (score >= 50) return "Medium";
    if (score >= 30) return "Low";
    return "Normal";
}

static string levelClass(double score) {
    if (score >= 75) return "high";
    if (score >= 50) return "medium";
    if (score >= 30) return "low";
    return "ok";
}

static string formatNum(double value, int digits) {
    ostringstream out;
    out << fixed << setprecision(digits) << value;
    return out.str();
}

void writeDashboard(const vector<ScoredProcess>& rows, const string& scanTime) {
    vector<ScoredProcess> sorted = rows;
    sort(sorted.begin(), sorted.end(), compareScore);

    int alertCount = 0;
    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i].score.score >= ALERT_THRESHOLD) {
            alertCount++;
        }
    }

    string path = getExeFolder() + "\\web\\dashboard.html";
    CreateDirectoryA((getExeFolder() + "\\web").c_str(), NULL);

    ofstream file(path.c_str());
    if (!file) {
        return;
    }

    file <<
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<title>ProcessSentinel Dashboard</title>\n"
        "<style>\n"
        "body{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;}\n"
        "header{background:#1e293b;padding:20px 28px;border-bottom:3px solid #38bdf8;}\n"
        "h1{margin:0;font-size:26px;} .sub{color:#94a3b8;margin-top:6px;}\n"
        ".wrap{padding:22px 28px;}\n"
        ".cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px;}\n"
        ".card{background:#1e293b;border-radius:10px;padding:16px 18px;min-width:160px;flex:1;}\n"
        ".card b{display:block;font-size:26px;color:#38bdf8;}\n"
        "table{width:100%;border-collapse:collapse;background:#1e293b;}\n"
        "th,td{padding:8px 10px;border-bottom:1px solid #334155;text-align:left;font-size:13px;}\n"
        "th{background:#0f172a;color:#93c5fd;}\n"
        "tr.high{background:#7f1d1d;}\n"
        "tr.medium{background:#7c2d12;}\n"
        "tr.low{background:#1e3a5f;}\n"
        ".tag{padding:3px 8px;border-radius:999px;font-size:12px;}\n"
        ".tag.high{background:#ef4444;color:white;}\n"
        ".tag.medium{background:#f59e0b;color:black;}\n"
        ".tag.low{background:#38bdf8;color:black;}\n"
        ".tag.ok{background:#22c55e;color:black;}\n"
        "h2{margin-top:28px;}\n"
        ".box{background:#1e293b;padding:16px;border-radius:10px;line-height:1.5;}\n"
        "</style>\n</head>\n<body>\n"
        "<header>\n"
        "<h1>ProcessSentinel</h1>\n"
        "<div class=\"sub\">Windows process monitoring using 4 behavior parameters</div>\n"
        "<div class=\"sub\">Last scan: " << htmlEscape(scanTime) << "</div>\n"
        "</header>\n<div class=\"wrap\">\n";

    file << "<div class=\"cards\">"
         << "<div class=\"card\">Processes scanned<b>" << sorted.size() << "</b></div>"
         << "<div class=\"card\">Alerts this scan<b>" << alertCount << "</b></div>"
         << "<div class=\"card\">Snapshots in DB<b>" << countSnapshots() << "</b></div>"
         << "<div class=\"card\">Baselines learned<b>" << countBaselines() << "</b></div>"
         << "</div>\n";

    file << "<h2>Current processes</h2>\n"
         << "<table>\n<tr>"
         << "<th>PID</th><th>Name</th><th>Parent</th><th>CPU %</th><th>Memory MB</th>"
         << "<th>Threads</th><th>Net</th><th>Children</th>"
         << "<th>B</th><th>P</th><th>N</th><th>R</th><th>Score S</th><th>Level</th>"
         << "</tr>\n";

    size_t show = sorted.size();
    if (show > 80) show = 80;
    for (size_t i = 0; i < show; i++) {
        const ScoredProcess& row = sorted[i];
        file << "<tr class=\"" << levelClass(row.score.score) << "\">"
             << "<td>" << row.info.pid << "</td>"
             << "<td>" << htmlEscape(row.info.name) << "</td>"
             << "<td>" << htmlEscape(row.info.parentName) << "</td>"
             << "<td>" << formatNum(row.info.cpuPercent, 1) << "</td>"
             << "<td>" << formatNum(row.info.memoryMB, 1) << "</td>"
             << "<td>" << row.info.numThreads << "</td>"
             << "<td>" << row.info.numConnections << "</td>"
             << "<td>" << row.info.childCount << "</td>"
             << "<td>" << formatNum(row.score.scoreB, 0) << "</td>"
             << "<td>" << formatNum(row.score.scoreP, 0) << "</td>"
             << "<td>" << formatNum(row.score.scoreN, 0) << "</td>"
             << "<td>" << formatNum(row.score.scoreR, 0) << "</td>"
             << "<td><b>" << formatNum(row.score.score, 1) << "</b></td>"
             << "<td><span class=\"tag " << levelClass(row.score.score) << "\">"
             << levelText(row.score.score) << "</span></td>"
             << "</tr>\n";
    }
    file << "</table>\n";

    file << "<h2>Why a process was flagged</h2>\n<table>\n"
         << "<tr><th>Name</th><th>Score</th><th>Reasons</th></tr>\n";
    int shownReasons = 0;
    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i].score.score >= ALERT_THRESHOLD) {
            file << "<tr>"
                 << "<td>" << htmlEscape(sorted[i].info.name) << " (" << sorted[i].info.pid << ")</td>"
                 << "<td>" << formatNum(sorted[i].score.score, 1) << "</td>"
                 << "<td>" << htmlEscape(sorted[i].score.reasons) << "</td>"
                 << "</tr>\n";
            shownReasons++;
            if (shownReasons >= 20) break;
        }
    }
    if (shownReasons == 0) {
        file << "<tr><td colspan=\"3\">No process crossed the alert threshold (50) in this scan.</td></tr>\n";
    }
    file << "</table>\n";

    file <<
        "<h2>How the 4 parameters work</h2>\n"
        "<div class=\"box\">"
        "<p><b>B Process Behavior Deviation (30%)</b> CPU, memory and thread count compared with the stored baseline.</p>"
        "<p><b>P Process Relationship Anomaly (25%)</b> Unexpected parent process or unusual child-process count.</p>"
        "<p><b>N Network and File Activity Anomaly (25%)</b> Unusual TCP connections and I/O operations.</p>"
        "<p><b>R Security-Sensitive Behavior (20%)</b> Temp-folder programs, system-name mismatch, and similar signals.</p>"
        "<p>Final score: <b>S = 0.30B + 0.25P + 0.25N + 0.20R</b></p>"
        "<p>These weights are starting values for the project. An alert is not proof of malware.</p>"
        "</div>\n"
        "</div></body></html>\n";
}

void openDashboard() {
    string path = getExeFolder() + "\\web\\dashboard.html";
    ShellExecuteA(NULL, "open", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

static bool compareScore(const ScoredProcess& a, const ScoredProcess& b) {
    return a.score.score > b.score.score;
}

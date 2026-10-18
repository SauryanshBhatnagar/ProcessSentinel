#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <windows.h>

#include "process_monitor.h"
#include "detector.h"
#include "database.h"
#include "html_report.h"

using namespace std;

static bool g_includeDemo = false;

void printBanner() {
    cout << "----------------------------------------------\n";
    cout << "   ProcessSentinel  (Team ID008)\n";
    cout << "   4-parameter process behavior monitor\n";
    cout << "-----------------------------------------------\n";
}

void printMenu() {
    cout << "\n1. Scan processes now\n";
    cout << "2. Auto monitor (5 scans)\n";
    cout << "3. Show recent alerts\n";
    cout << "4. Toggle demo suspicious process (now: "
         << (g_includeDemo ? "ON" : "OFF") << ")\n";
    cout << "5. Open HTML dashboard\n";
    cout << "6. Database summary\n";
    cout << "0. Exit\n";
    cout << "Enter choice: ";
}

vector<ScoredProcess> runOneScan(bool quiet) {
    if (!quiet) {
        cout << "\nCollecting Windows process data. Please wait...\n";
    }

    vector<ProcessInfo> processes = collectProcesses();
    if (g_includeDemo) {
        processes.push_back(makeDemoProcess());
        saveEvent(99999, "update_helper.exe", "demo",
                  "Demo suspicious process added for testing");
    }

    vector<ScoredProcess> rows;
    int alertCount = 0;

    for (size_t i = 0; i < processes.size(); i++) {
        ProcessInfo proc = processes[i];
        Baseline base = getBaseline(proc.name);
        ScoreResult score = scoreProcess(proc, base);

        saveSnapshot(proc);
        updateBaseline(proc);

        if (score.score >= ALERT_THRESHOLD) {
            saveAlert(score, proc.capturedAt);
            alertCount++;
        }

        ScoredProcess row;
        row.info = proc;
        row.score = score;
        rows.push_back(row);
    }

    writeDashboard(rows, currentTimeText());
    if (!quiet) {
        cout << "Scanned " << processes.size() << " processes. Alerts: " << alertCount << "\n";
    }
    return rows;
}

void printTopScores(const vector<ScoredProcess>& rows) {
    bool taken[4096];
    int n = (int)rows.size();
    if (n > 4096) n = 4096;
    for (int i = 0; i < n; i++) {
        taken[i] = false;
    }

    cout << left << setw(8) << "PID" << setw(24) << "Name"
         << setw(8) << "B" << setw(8) << "P" << setw(8) << "N"
         << setw(8) << "R" << setw(8) << "S" << "Level\n";
    cout << "----------------------------------------------------------------------\n";

    for (int shown = 0; shown < 12; shown++) {
        int best = -1;
        for (int i = 0; i < n; i++) {
            if (taken[i]) continue;
            if (best == -1 || rows[i].score.score > rows[best].score.score) {
                best = i;
            }
        }
        if (best == -1) break;
        taken[best] = true;
        double s = rows[best].score.score;
        string level = "Normal";
        if (s >= 75) level = "High";
        else if (s >= 50) level = "Medium";
        else if (s >= 30) level = "Low";

        cout << left << setw(8) << rows[best].info.pid
             << setw(24) << rows[best].info.name.substr(0, 23)
             << setw(8) << (int)rows[best].score.scoreB
             << setw(8) << (int)rows[best].score.scoreP
             << setw(8) << (int)rows[best].score.scoreN
             << setw(8) << (int)rows[best].score.scoreR
             << setw(8) << (int)s
             << level << "\n";
    }
}

void showAlerts() {
    vector<AlertRow> alerts = getRecentAlerts(15);
    if (alerts.empty()) {
        cout << "No alerts stored yet. Run a scan first.\n";
        return;
    }
    cout << "\nRecent alerts:\n";
    for (size_t i = 0; i < alerts.size(); i++) {
        cout << "- " << alerts[i].name << " (PID " << alerts[i].pid
             << ")  S=" << (int)alerts[i].score
             << "  [" << alerts[i].capturedAt << "]\n  "
             << alerts[i].reasons << "\n";
    }
}

int main() {
    printBanner();

    if (!initDatabase()) {
        cout << "Database setup failed.\n";
        return 1;
    }

    bool running = true;
    while (running) {
        printMenu();
        int choice = -1;
        cin >> choice;
        if (cin.fail()) {
            cin.clear();
            cin.ignore(1000, '\n');
            cout << "Please enter a number.\n";
            continue;
        }

        if (choice == 1) {
            vector<ScoredProcess> rows = runOneScan(true);
            cout << "\nScanned " << rows.size() << " processes.\n";
            cout << "Dashboard saved to web\\dashboard.html\n\n";
            printTopScores(rows);
        } else if (choice == 2) {
            cout << "Running 5 scans. Each scan waits a few seconds...\n";
            for (int i = 1; i <= 5; i++) {
                cout << "\nScan " << i << " of 5...\n";
                vector<ScoredProcess> rows = runOneScan(true);
                printTopScores(rows);
                if (i < 5) {
                    Sleep(4000);
                }
            }
        } else if (choice == 3) {
            showAlerts();
        } else if (choice == 4) {
            g_includeDemo = !g_includeDemo;
            cout << "Demo suspicious process is now "
                 << (g_includeDemo ? "ON" : "OFF") << ".\n";
            cout << "Turn it ON, then choose 1 to see a high suspicion score.\n";
        } else if (choice == 5) {
            openDashboard();
            cout << "Opened web\\dashboard.html in your browser.\n";
        } else if (choice == 6) {
            cout << "Snapshots: " << countSnapshots() << "\n";
            cout << "Alerts: " << countAlerts() << "\n";
            cout << "Baselines: " << countBaselines() << "\n";
            cout << "Database file: sentinel.db\n";
        } else if (choice == 0) {
            running = false;
        } else {
            cout << "Invalid choice.\n";
        }
    }

    closeDatabase();
    cout << "Goodbye.\n";
    return 0;
}

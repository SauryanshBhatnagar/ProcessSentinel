#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <vector>
#include "process_monitor.h"
#include "detector.h"

bool initDatabase();
void closeDatabase();

void saveSnapshot(const ProcessInfo& proc);
Baseline getBaseline(const std::string& processName);
void updateBaseline(const ProcessInfo& proc);
void saveAlert(const ScoreResult& result, const std::string& capturedAt);
void saveEvent(int pid, const std::string& name, const std::string& type, const std::string& details);

struct AlertRow {
    int pid;
    std::string name;
    double score;
    double scoreB;
    double scoreP;
    double scoreN;
    double scoreR;
    std::string reasons;
    std::string capturedAt;
};

std::vector<AlertRow> getRecentAlerts(int limit);
int countSnapshots();
int countAlerts();
int countBaselines();

#endif

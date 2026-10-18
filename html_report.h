#ifndef HTML_REPORT_H
#define HTML_REPORT_H

#include <string>
#include <vector>
#include "process_monitor.h"
#include "detector.h"

struct ScoredProcess {
    ProcessInfo info;
    ScoreResult score;
};

void writeDashboard(const std::vector<ScoredProcess>& rows, const std::string& scanTime);
void openDashboard();

#endif

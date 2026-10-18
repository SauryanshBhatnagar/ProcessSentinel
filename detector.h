#ifndef DETECTOR_H
#define DETECTOR_H

#include <string>
#include "process_monitor.h"

// Stored "normal" values for a process name.
struct Baseline {
    std::string processName;
    double avgCpu;
    double avgMemory;
    double avgThreads;
    double avgConnections;
    double avgIo;
    double avgChildren;
    int sampleCount;
    std::string usualParents;
    bool found;
};

// Scores for the 4 Sentinel parameters (each 0 to 100).
struct ScoreResult {
    int pid;
    std::string name;
    double scoreB;  // Process Behavior Deviation
    double scoreP;  // Process Relationship Anomaly
    double scoreN;  // Network and File Activity Anomaly
    double scoreR;  // Security-Sensitive Behavior
    double score;   // Final suspicion score
    std::string reasons;
};

ScoreResult scoreProcess(const ProcessInfo& proc, const Baseline& base);

// S = 0.30B + 0.25P + 0.25N + 0.20R
const double WEIGHT_B = 0.30;
const double WEIGHT_P = 0.25;
const double WEIGHT_N = 0.25;
const double WEIGHT_R = 0.20;
const double ALERT_THRESHOLD = 50.0;

#endif

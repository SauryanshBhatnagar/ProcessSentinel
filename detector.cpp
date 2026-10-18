#include "detector.h"
#include <sstream>
#include <algorithm>
#include <cctype>

using namespace std;

static string lowerCopy(string text) {
    for (size_t i = 0; i < text.size(); i++) {
        text[i] = (char)tolower((unsigned char)text[i]);
    }
    return text;
}

static bool containsIgnoreCase(const string& text, const string& part) {
    return lowerCopy(text).find(lowerCopy(part)) != string::npos;
}

static bool parentIsKnown(const string& usualParents, const string& parentName) {
    if (parentName.empty() || parentName == "unknown") {
        return true;
    }
    string all = lowerCopy(usualParents);
    string parent = lowerCopy(parentName);
    if (all.empty()) {
        return true;
    }
    return all.find(parent) != string::npos;
}

// If current is much higher than the baseline, return a higher score.
static double deviationScore(double current, double baseline) {
    if (baseline < 0.5) {
        if (current <= 2.0) {
            return 0.0;
        }
        if (current >= 60.0) {
            return 90.0;
        }
        return current * 1.2;
    }

    double ratio = current / baseline;
    if (ratio <= 1.5) {
        return 0.0;
    }
    if (ratio >= 5.0) {
        return 100.0;
    }
    return ((ratio - 1.5) / 3.5) * 100.0;
}

static bool looksLikeSystemName(const string& name) {
    string n = lowerCopy(name);
    return n == "svchost.exe" || n == "lsass.exe" || n == "csrss.exe" ||
           n == "services.exe" || n == "winlogon.exe" || n == "explorer.exe" ||
           n == "smss.exe" || n == "wininit.exe";
}

static bool isSystemFolder(const string& path) {
    string p = lowerCopy(path);
    return p.find("\\windows\\system32") != string::npos ||
           p.find("\\windows\\syswow64") != string::npos ||
           p.find("\\windows\\explorer.exe") != string::npos;
}

ScoreResult scoreProcess(const ProcessInfo& proc, const Baseline& base) {
    ScoreResult result;
    result.pid = proc.pid;
    result.name = proc.name;
    result.scoreB = 0;
    result.scoreP = 0;
    result.scoreN = 0;
    result.scoreR = 0;
    result.score = 0;

    ostringstream reasons;

    double cpuScore = deviationScore(proc.cpuPercent, base.found ? base.avgCpu : 0);
    double memScore = deviationScore(proc.memoryMB, base.found ? base.avgMemory : 5.0);
    double threadScore = deviationScore(proc.numThreads, base.found ? base.avgThreads : 4.0);
    result.scoreB = (cpuScore + memScore + threadScore) / 3.0;

    if (cpuScore >= 40) {
        reasons << "CPU usage is higher than the normal baseline. ";
    }
    if (memScore >= 40) {
        reasons << "Memory usage is higher than the normal baseline. ";
    }
    if (threadScore >= 40) {
        reasons << "Thread count is unusual for this process. ";
    }

    double parentScore = 0;
    if (base.found && base.sampleCount >= 6) {
        if (!parentIsKnown(base.usualParents, proc.parentName)) {
            parentScore += 70;
            reasons << "Parent process '" << proc.parentName
                    << "' is not a usual parent for " << proc.name << ". ";
        }
    }
    double childScore = deviationScore(proc.childCount, base.found ? base.avgChildren : 1.0);
    if (childScore >= 50) {
        parentScore += 40;
        reasons << "This process created an unusual number of child processes. ";
    }
    if (parentScore > 100) parentScore = 100;
    result.scoreP = parentScore;

    double connScore = deviationScore(proc.numConnections, base.found ? base.avgConnections : 0);
    double ioScore = deviationScore((double)proc.ioOperations, base.found ? base.avgIo : 100.0);
    result.scoreN = (connScore + ioScore) / 2.0;
    if (connScore >= 40) {
        reasons << "Network connection count is unusual. ";
    }
    if (ioScore >= 50) {
        reasons << "File / I/O activity is higher than normal. ";
    }

    double security = 0;
    string path = proc.exePath;
    if (containsIgnoreCase(path, "\\temp\\") || containsIgnoreCase(path, "\\appdata\\local\\temp")) {
        security += 70;
        reasons << "Program is running from a Temp folder. ";
    }
    if (looksLikeSystemName(proc.name) && !path.empty() && !isSystemFolder(path)) {
        security += 85;
        reasons << "Name looks like a Windows system process but the file path is not in System32. ";
    }
    if (proc.childCount >= 12) {
        security += 35;
        reasons << "Very high child-process count can be a security signal. ";
    }
    string lowName = lowerCopy(proc.name);
    if ((lowName == "notepad.exe" || lowName == "calc.exe" || lowName == "mspaint.exe") &&
        proc.numConnections >= 8) {
        security += 50;
        reasons << "A simple desktop program is making many network connections. ";
    }
    if (security > 100) security = 100;
    result.scoreR = security;

    // While we are still learning a process, keep B/P/N milder.
    // Security flags (R) are not reduced, because they do not need a long history.
    if ((!base.found || base.sampleCount < 5) && result.scoreR < 50) {
        result.scoreB *= 0.45;
        result.scoreP *= 0.45;
        result.scoreN *= 0.45;
        if (reasons.str().empty()) {
            reasons << "Still learning the normal baseline for this process. ";
        }
    }

    result.score = WEIGHT_B * result.scoreB +
                   WEIGHT_P * result.scoreP +
                   WEIGHT_N * result.scoreN +
                   WEIGHT_R * result.scoreR;

    if (result.scoreB > 100) result.scoreB = 100;
    if (result.scoreP > 100) result.scoreP = 100;
    if (result.scoreN > 100) result.scoreN = 100;
    if (result.scoreR > 100) result.scoreR = 100;
    if (result.score > 100) result.score = 100;

    if (reasons.str().empty()) {
        reasons << "Behavior is close to the learned baseline.";
    }
    result.reasons = reasons.str();
    return result;
}

#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <string>
#include <vector>

// One snapshot of a running process.
struct ProcessInfo {
    int pid;
    int ppid;
    std::string name;
    std::string parentName;
    std::string exePath;
    double cpuPercent;
    double memoryMB;
    int numThreads;
    int numConnections;
    long long ioOperations;
    int childCount;
    std::string capturedAt;
};

// Collect current Windows processes using OS APIs.
std::vector<ProcessInfo> collectProcesses();

// Fake suspicious process used in viva / demo.
ProcessInfo makeDemoProcess();

std::string currentTimeText();
std::string getExeFolder();

#endif

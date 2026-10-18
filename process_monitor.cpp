#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>

#include <map>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

#include "process_monitor.h"

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

using namespace std;

string currentTimeText() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    ostringstream out;
    out << st.wYear << "-"
        << setfill('0') << setw(2) << st.wMonth << "-"
        << setw(2) << st.wDay << " "
        << setw(2) << st.wHour << ":"
        << setw(2) << st.wMinute << ":"
        << setw(2) << st.wSecond;
    return out.str();
}

string getExeFolder() {
    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    string path = buf;
    size_t pos = path.find_last_of("\\/");
    if (pos == string::npos) {
        return ".";
    }
    return path.substr(0, pos);
}

static unsigned long long fileTimeToNumber(const FILETIME& ft) {
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

static string getProcessPath(DWORD pid) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (handle == NULL) {
        handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (handle == NULL) {
        return "";
    }

    char path[MAX_PATH];
    path[0] = '\0';
    if (GetModuleFileNameExA(handle, NULL, path, MAX_PATH) == 0) {
        path[0] = '\0';
    }
    CloseHandle(handle);
    return path;
}

static double getMemoryMB(DWORD pid) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (handle == NULL) {
        return 0.0;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    double memoryMB = 0.0;
    if (GetProcessMemoryInfo(handle, &pmc, sizeof(pmc))) {
        memoryMB = pmc.WorkingSetSize / (1024.0 * 1024.0);
    }
    CloseHandle(handle);
    return memoryMB;
}

static long long getIoOperations(DWORD pid) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (handle == NULL) {
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (handle == NULL) {
        return 0;
    }

    IO_COUNTERS io;
    long long total = 0;
    if (GetProcessIoCounters(handle, &io)) {
        total = (long long)(io.ReadOperationCount + io.WriteOperationCount);
    }
    CloseHandle(handle);
    return total;
}

static unsigned long long getProcessCpuTime(DWORD pid) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (handle == NULL) {
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (handle == NULL) {
        return 0;
    }

    FILETIME createTime, exitTime, kernelTime, userTime;
    unsigned long long total = 0;
    if (GetProcessTimes(handle, &createTime, &exitTime, &kernelTime, &userTime)) {
        total = fileTimeToNumber(kernelTime) + fileTimeToNumber(userTime);
    }
    CloseHandle(handle);
    return total;
}

static map<DWORD, int> countTcpConnections() {
    map<DWORD, int> counts;

    DWORD bytes = 0;
    GetExtendedTcpTable(NULL, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (bytes == 0) {
        return counts;
    }

    vector<char> buffer(bytes);
    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)&buffer[0];
    if (GetExtendedTcpTable(table, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            DWORD pid = table->table[i].dwOwningPid;
            counts[pid] = counts[pid] + 1;
        }
    }
    return counts;
}

vector<ProcessInfo> collectProcesses() {
    vector<ProcessInfo> processes;
    map<DWORD, string> names;
    map<DWORD, int> threadCount;
    map<DWORD, DWORD> parents;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return processes;
    }

    do {
        names[entry.th32ProcessID] = entry.szExeFile;
        threadCount[entry.th32ProcessID] = (int)entry.cntThreads;
        parents[entry.th32ProcessID] = entry.th32ParentProcessID;
    } while (Process32Next(snapshot, &entry));
    CloseHandle(snapshot);

    map<DWORD, int> childCount;
    for (map<DWORD, DWORD>::iterator it = parents.begin(); it != parents.end(); ++it) {
        childCount[it->second] = childCount[it->second] + 1;
    }

    map<DWORD, int> connections = countTcpConnections();

    // First CPU sample
    map<DWORD, unsigned long long> cpuStart;
    unsigned long long wallStart = GetTickCount();
    for (map<DWORD, string>::iterator it = names.begin(); it != names.end(); ++it) {
        cpuStart[it->first] = getProcessCpuTime(it->first);
    }

    Sleep(400);

    unsigned long long wallEnd = GetTickCount();
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int cpuCount = (int)sysInfo.dwNumberOfProcessors;
    if (cpuCount <= 0) {
        cpuCount = 1;
    }

    unsigned long long wallDiff = (wallEnd - wallStart) * 10000ULL; // ms to 100-ns units
    string now = currentTimeText();

    for (map<DWORD, string>::iterator it = names.begin(); it != names.end(); ++it) {
        DWORD pid = it->first;
        ProcessInfo info;
        info.pid = (int)pid;
        info.ppid = (int)parents[pid];
        info.name = it->second;
        if (names.find(parents[pid]) != names.end()) {
            info.parentName = names[parents[pid]];
        } else {
            info.parentName = "unknown";
        }
        info.exePath = getProcessPath(pid);
        info.memoryMB = getMemoryMB(pid);
        info.numThreads = threadCount[pid];
        info.numConnections = connections[pid];
        info.ioOperations = getIoOperations(pid);
        info.childCount = childCount[pid];
        info.capturedAt = now;

        unsigned long long cpuEnd = getProcessCpuTime(pid);
        unsigned long long cpuDiff = 0;
        if (cpuEnd > cpuStart[pid]) {
            cpuDiff = cpuEnd - cpuStart[pid];
        }
        if (wallDiff > 0) {
            info.cpuPercent = (100.0 * (double)cpuDiff) / ((double)wallDiff * cpuCount);
        } else {
            info.cpuPercent = 0.0;
        }
        if (info.cpuPercent < 0) info.cpuPercent = 0;
        if (info.cpuPercent > 100) info.cpuPercent = 100;

        processes.push_back(info);
    }

    return processes;
}

ProcessInfo makeDemoProcess() {
    ProcessInfo demo;
    demo.pid = 99999;
    demo.ppid = 1111;
    demo.name = "update_helper.exe";
    demo.parentName = "WINWORD.EXE";
    demo.exePath = "C:\\Users\\Public\\AppData\\Local\\Temp\\update_helper.exe";
    demo.cpuPercent = 82.0;
    demo.memoryMB = 780.0;
    demo.numThreads = 46;
    demo.numConnections = 16;
    demo.ioOperations = 48000;
    demo.childCount = 11;
    demo.capturedAt = currentTimeText();
    return demo;
}

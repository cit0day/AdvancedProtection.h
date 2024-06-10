// AdvancedProtection.h
// Header file for advanced anti-debugging and anti-cracking techniques
// All the important steps are commented and explained give a star to the repo for more updates

// github: cit0day
// discord: nebraskaproject
// email: info@nebraskaproject.it

#ifndef ADVANCED_ANTI_DEBUG_H
#define ADVANCED_ANTI_DEBUG_H

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// Function to detect if a debugger is present
bool IsDebuggerPresentCustom() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent;
}

// Function to detect hardware breakpoints
bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }
    return false;
}

// Function to check for common debugging windows
bool IsDebuggingWindowPresent() {
    const std::vector<std::wstring> windowsToCheck = {
        L"OLLYDBG",           // OllyDbg
        L"WinDbgFrameClass",  // WinDbg
        L"ID",                // IDA Pro
        L"IMMClass",          // Immunity Debugger
        L"ImmunityDebugger",  // Immunity Debugger alternative
        L"Debug",             // Generic debug
        L"GHIDRA",            // Ghidra
        L"x32dbg",            // x32dbg
        L"x64dbg",            // x64dbg
        L"disassembly",       // Generic disassembly
        L"cheatengine",       // Cheat Engine
        L"IDA",               // IDA Pro
        L"OLLYICE",           // OllyICE
        L"DbgViewClass",      // Debug View
        L"Scylla",            // Scylla
        L"WinDbg",            // WinDbg
        L"DbgviewClass",      // Dbgview
        L"protection_id",     // Protection ID
        L"idaq",              // IDA Pro
        L"idaq64",            // IDA Pro
        L"ida64",             // IDA Pro
        L"ida32",             // IDA Pro
        L"syser",             // Syser
        L"lordpe",            // LordPE
        L"captainhook",       // Captain Hook
        L"hookshark",         // Hook Shark
        L"fakenet",           // FakeNet
        L"windsock",          // WindSock
        L"tcpview",           // TCPView
        L"winhex",            // WinHex
        L"filemon",           // FileMon
        L"regmon",            // RegMon
        L"softice",           // SoftICE
        L"vmware",            // VMWare
        L"virtualbox",        // VirtualBox
        L"wine",              // Wine
        L"qemu",              // QEMU
        L"bochs",             // Bochs
        L"codevein",          // CodeVein
        L"resourcehacker",    // Resource Hacker
        L"reshacker"          // Resource Hacker
    };

    for (const auto& windowName : windowsToCheck) {
        if (FindWindowW(windowName.c_str(), NULL)) {
            return true;
        }
    }
    return false;
}

// Function to detect if the process is being debugged through output debug string
bool CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("Anti-debugging test");
    if (GetLastError() != 0) {
        return true;
    }
    return false;
}

// Function to detect if a process is running under a debugger using NtQueryInformationProcess
bool CheckNtQueryInformationProcess() {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
    NTSTATUS status;
    DWORD noDebugInherit = 0;
    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (hNtDll == NULL) return false;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (NtQIP == NULL) return false;

    status = NtQIP(GetCurrentProcess(), 0x1f, &noDebugInherit, sizeof(DWORD), NULL);
    if (status != 0x00000000) return false;

    if (noDebugInherit == 0x1) return true;

    return false;
}

// Function to detect if a process is being debugged through the PEB structure
bool CheckPEBBeingDebugged() {
    __asm {
        mov eax, fs:[30h]
        movzx eax, byte ptr [eax+2]
    }
}

// Function to detect timing discrepancies caused by debugging
bool CheckTimingDiscrepancies() {
    const DWORD sleepTime = 1000;
    DWORD startTime = GetTickCount();
    Sleep(sleepTime);
    DWORD endTime = GetTickCount();

    if ((endTime - startTime) < sleepTime) {
        return true;
    }
    return false;
}

// Function to detect software breakpoints by checking memory protection
bool CheckSoftwareBreakpoints() {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* pMem = (unsigned char*)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    for (size_t i = 0; i < 4096; i++) {
        if (pMem[i] == 0xCC) {
            return true;
        }
    }
    return false;
}

// Function to detect Cheat Engine driver
bool CheckCheatEngineDriver() {
    HANDLE hDevice = CreateFileA("\\\\.\\CEDRIVER72", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}

// Function to detect x64dbg driver
bool Checkx64dbgDriver() {
    HANDLE hDevice = CreateFileA("\\\\.\\x64dbg", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}

// Function to detect driver associated with a program
bool CheckProgramDriver(const std::wstring& driverName) {
    HANDLE hDevice = CreateFileW(driverName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}

// Function to perform self-debugging
bool SelfDebug() {
    // Insert self-debugging mechanism here
    // This function should return true if the process detects it is being debugged by itself
    // Otherwise, return false
}

// Main function to check all anti-debugging techniques
bool PerformAntiDebugChecks() {
    if (IsDebuggerPresentCustom()) {
        std::cout << "Debugger detected: IsDebuggerPresentCustom" << std::endl;
        return true;
    }

    if (CheckHardwareBreakpoints()) {
        std::cout << "Debugger detected: CheckHardwareBreakpoints" << std::endl;
        return true;
    }

    if (IsDebuggingWindowPresent()) {
        std::cout << "Debugger detected: IsDebuggingWindowPresent" << std::endl;
        return true;
    }

    if (CheckOutputDebugString()) {
        std::cout << "Debugger detected: CheckOutputDebugString" << std::endl;
        return true;
    }

    if (CheckNtQueryInformationProcess()) {
        std::cout << "Debugger detected: CheckNtQueryInformationProcess" << std::endl;
        return true;
    }

    if (CheckPEBBeingDebugged()) {
        std::cout << "Debugger detected: CheckPEBBeingDebugged" << std::endl;
        return true;
    }

    if (CheckTimingDiscrepancies()) {
        std::cout << "Debugger detected: CheckTimingDiscrepancies" << std::endl;
        return true;
    }

    if (CheckSoftwareBreakpoints()) {
        std::cout << "Debugger detected: CheckSoftwareBreakpoints" << std::endl;
        return true;
    }

    if (CheckCheatEngineDriver()) {
        std::cout << "Debugger detected: CheckCheatEngineDriver" << std::endl;
        return true;
    }

    if (Checkx64dbgDriver()) {
        std::cout << "Debugger detected: Checkx64dbgDriver" << std::endl;
        return true;
    }

    // Add checks for drivers associated with programs listed in IsDebuggingWindowPresent
    const std::vector<std::wstring> programDrivers = {
        L"\\\\.\\CEDRIVER72",  // Cheat Engine driver
        L"\\\\.\\x64dbg"       // x64dbg driver
        // Add more drivers here if needed
    };

    for (const auto& driver : programDrivers) {
        if (CheckProgramDriver(driver)) {
            std::cout << "Debugger detected: CheckProgramDriver" << std::endl;
            return true;
        }
    }

    // Perform self-debugging check
    if (SelfDebug()) {
        std::cout << "Debugger detected: SelfDebug" << std::endl;
        return true;
    }

    return false;
}

#endif // ADVANCED_ANTI_DEBUG_H

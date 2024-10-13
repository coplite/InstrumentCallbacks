#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <DbgHelp.h>
#include <cstdint>

#define ProcessInstrumentationCallback 0x28

typedef NTSTATUS(NTAPI* NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

int counter = 0;
bool flag = false;

void Hooker()
{
    __asm("pop r10");
    __asm("push 2000");
}

int main()
{
    NtSetInformationProcess NtSetInfoProc = (NtSetInformationProcess)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtSetInformationProcess");
    if(NtSetInfoProc == NULL)
    {
        std::cout << "[-] Unable to resolve NtSetInformationProcess!!";
        exit(-1);
    }
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    
    InstrumentationCallbackInfo.Version = 0; // 0 is x64 and 1 for x86
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = (PVOID)(DWORD64)Hooker;
    
    std::cout << "[*] Performing instrumentation!!\n";

    NtSetInfoProc(GetCurrentProcess(), static_cast<PROCESS_INFORMATION_CLASS>(0x28), &InstrumentationCallbackInfo, sizeof(InstrumentationCallbackInfo));    
    
    Sleep(500);
}

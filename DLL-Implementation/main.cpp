#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <DbgHelp.h>
#include <cstdint>
#include <psapi.h>
#include <tlhelp32.h>
#include <fstream>

// g++ -shared main.cpp proxy.obj -lkernel32 -lntdll -ldbghelp -lpsapi -masm=intel -o payload.dll

#define ProcessInstrumentationCallback 0x28

extern "C" void proxy();
extern "C" void Hooker(CONTEXT* ctx);
typedef NTSTATUS(NTAPI* NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

static bool flag = false;

HANDLE hConsole;
char buffer[1024];
const char* filename = "Trace.log";
std::fstream file;
unsigned int counter = 0;

void Hooker(CONTEXT* ctx)
{
	uintptr_t pTEB = (uintptr_t)NtCurrentTeb();	
	ctx->Rip = *((uintptr_t*)(pTEB + 0x2d8));
	ctx->Rsp = *((uintptr_t*)(pTEB + 0x2e0));
	ctx->Rcx = ctx->R10;

	if(!flag)
	{
		flag = true;
		counter++;
		DWORD64 Displacement;
		PSYMBOL_INFO SymbolInfo;
		BYTE SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {0};
		SymbolInfo = (PSYMBOL_INFO)SymbolBuffer;
		SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		SymbolInfo->MaxNameLen = MAX_SYM_NAME;

		MODULEINFO mi;
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		GetModuleInformation((HANDLE)-1, hNtdll, &mi, sizeof(mi));

		bool SymbolLookupResult = SymFromAddr((HANDLE)-1, ctx->Rip, &Displacement, SymbolInfo);

		if(SymbolLookupResult)
		{
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);			
			sprintf((char*)buffer, "[+] Function: %s is located at [0x%p]\n", SymbolInfo->Name, ctx->Rip-2);
			std::cout << buffer;
			file << buffer;
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
		else
		{
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);			
			sprintf((char*)buffer, "[!] Function: UNKNOWN is located at [0x%p]\n", ctx->Rip-2);
			std::cout << buffer;
			file << buffer;
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
		
		if(!((ctx->Rip)-2 > (DWORD64)hNtdll) && ((ctx->Rip)-2 < ((DWORD64)hNtdll + mi.SizeOfImage)))
		{
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);			// i might change formatting of this a bit who knows			
			sprintf((char*)buffer, "   \\__[-] Direct Syscall detected, performing immediate termination!!\n");
			std::cout << buffer;
			file << buffer;
			
			sprintf((char*)buffer, "    \\____[Location of syscall:     		0x%p]\n", ctx->Rip-2);
			std::cout << buffer;
			file << buffer;
			
			sprintf((char*)buffer, "     \\______[Ntdll base address:  	 	0x%p]\n", (DWORD64)hNtdll);
			std::cout << buffer;
			file << buffer;
			
			sprintf((char*)buffer, "      \\________[Ntdll end address: 		0x%p]\n", (DWORD64)hNtdll + mi.SizeOfImage);
			std::cout << buffer;
			file << buffer;
			
			sprintf((char*)buffer, "       \\________[Return Value:                                 0x%llx]\n", (ctx->Rax));
			std::cout << buffer;
			file << buffer;

			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

			exit(-1);
		}
		/*
		else if(counter % 2 == 1) // counter is an odd number
		{
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
			sprintf((char*)buffer, "   \\__[-] Indirect Syscall detected, performing immediate termination!!\n");
			std::cout << buffer;
			file << buffer;
			
			sprintf((char*)buffer, "    \\________[Return Value:	0x%llx]\n", (ctx->Rax));
			std::cout << buffer;
			file << buffer;
			
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			exit(-1);
		}
		*/
		else
		{
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

			sprintf((char*)buffer, "   \\__[+] Normal Syscall!!\n");
			std::cout << buffer;
			file << buffer;
			
			sprintf((char*)buffer, "    \\__[Return Value: 0x%llx]\n");
			std::cout << buffer;
			file << buffer;
			
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
		flag = false;
	}
	RtlRestoreContext(ctx, NULL);
}


bool __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch(dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			if (hConsole == INVALID_HANDLE_VALUE)
			{
				std::cout << "[-] Unable to get std handle!!";
				exit(-1);
			}
			SymSetOptions(SYMOPT_UNDNAME);
			SymInitialize((HANDLE)-1, NULL, true);
			
			file.open(filename, std::ios::out | std::ios::app);
			
			if (!file.is_open())
			{
				std::cerr << "Failed to open the file." << std::endl;
				exit(-1);
			}
			
			// start inline hooking
			// hooking for indirect syscalls
			// end hooking
			NtSetInformationProcess NtSetInfoProc = (NtSetInformationProcess)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtSetInformationProcess");
			if(NtSetInfoProc == NULL)
			{
				std::cout << "[-] Unable to resolve NtSetInformationProcess!!";
				exit(-1);
			}
			PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;

			InstrumentationCallbackInfo.Version = 0; // 0 is x64 and 1 for x86
			InstrumentationCallbackInfo.Reserved = 0;
			InstrumentationCallbackInfo.Callback = (PVOID)(ULONG_PTR)proxy; // (PVOID)(DWORD64)Hooker or (PVOID)(ULONG_PTR)proxy

			NtSetInfoProc((HANDLE)-1, (PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback, &InstrumentationCallbackInfo, sizeof(InstrumentationCallbackInfo));
			break;
		}
		case DLL_PROCESS_DETACH:
		{
			file.close();
			break;
		}
	}
	return true;
}

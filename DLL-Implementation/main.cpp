#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <DbgHelp.h>
#include <cstdint>
#include <psapi.h>
#include <tlhelp32.h>

// g++ -shared main.cpp proxy.obj -lkernel32 -lntdll -ldbghelp -lpsapi -o payload.dll

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

void Hooker(CONTEXT* ctx)
{
	uintptr_t pTEB = (uintptr_t)NtCurrentTeb();	
	ctx->Rip = *((uintptr_t*)(pTEB + 0x2d8));
	ctx->Rsp = *((uintptr_t*)(pTEB + 0x2e0));
	ctx->Rcx = ctx->R10;

	if(!flag)
	{
		flag = true;

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
			printf("Function: %s is located at 0x%p\n", SymbolInfo->Name, ctx->Rip-2);	
		}
		else
		{
			printf("Function: UNKOWN is located at 0x%p\n", ctx->Rip-2);
		}
		if(!((ctx->Rip)-2 > (DWORD64)hNtdll) && ((ctx->Rip)-2 < ((DWORD64)hNtdll + mi.SizeOfImage)))
		{
			printf("[-] Direct Syscall detected, performing immediate termination!!\n");
			printf("Location:     0x%p\n", ctx->Rip-2);
			printf("NtDLL Base:   0x%p\n", (DWORD64)hNtdll);
			printf("NtDLL Offset: 0x%p\n", (DWORD64)hNtdll + mi.SizeOfImage);
			exit(-1);
		}
		else
		{
			printf("[+] Normal Syscall!!\n");
		}

		flag = false;
	}
	RtlRestoreContext(ctx, NULL);
}



/*
int main()
{
	
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize((HANDLE)-1, NULL, true);
	
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

}
*/

bool __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	static FILE *file = nullptr;
	switch(dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			SymSetOptions(SYMOPT_UNDNAME);
			SymInitialize((HANDLE)-1, NULL, true);
	
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
			break;
		}
	}
	return true;
}




/*


=================================ASM STUB



section .text
	extern Hooker
	extern RtlCaptureContext
	global proxy
	
proxy:	
    ; credits to https://gist.github.com/esoterix/df38008568c50d4f83123e3a90b62ebb
    mov gs:[0x2e0], rsp ; Win10 TEB InstrumentationCallbackPreviousSp
    mov gs:[0x2d8], r10 ; Win10 TEB InstrumentationCallbackPreviousPc
	
	mov r10, rcx ; save rcx
	sub rsp, 0x4d0 ; CONTEXT structure size
	and rsp, -16 ; align rsp
	mov rcx, rsp ; parameters are fun
	call RtlCaptureContext ; capture the thread's context
	
	sub rsp, 32 ; shadow stack space
	call callback ; call our callback which will restore context and go back to where we want
	
	int 3 ; we should not be here.
	
	
===================================Hooker Stub


void Hooker(CONTEXT* ctx)
{
	static int flag = 0;
	uintptr_t pTEB = (uintptr_t)NtCurrentTeb();
	
	ctx->Rip = *((uintptr_t*)(pTEB + 0x2d8));
	ctx->Rsp = *((uintptr_t*)(pTEB + 0x2e0));
	ctx->Rcx = ctx->R10;
	
	if(flag == 0)
	{
		flag = 1;
		printf("[!] Kernel invoked!!\n");
		flag = 0;
	}
	
	RtlRestoreContext(ctx, NULL);
}
*/
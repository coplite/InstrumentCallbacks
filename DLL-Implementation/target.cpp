#include <Windows.h>
#include <stdio.h>

// g++ target.cpp syscall.obj -o target

extern "C" NTSTATUS NtDelayExecution(bool Alertable, PLARGE_INTEGER DelayInterval);

int main()
{
	
	LARGE_INTEGER interval;
	interval.QuadPart = -2 * (1e7);  // sleep for 2 seconds
	
	system("pause");
	
	Sleep(2000);
	
	printf("[+] Sleep(2000) successfully ran, now executing direct syscall...\n");
	
	NtDelayExecution(false, &interval);
	
}

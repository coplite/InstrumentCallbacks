section .text
	global NtDelayExecution ; this is just direct syscall PoC
	
NtDelayExecution:	
	mov r10, rcx
	mov eax, 0x34
	syscall
	ret

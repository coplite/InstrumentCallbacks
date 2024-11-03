section .text
	global NtDelayExecution
	
NtDelayExecution:	
	mov r10, rcx
	mov eax, 0x34
	syscall
	ret

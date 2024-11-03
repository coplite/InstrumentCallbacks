section .text
	extern Hooker
	extern RtlCaptureContext
	global proxy
proxy:	
    mov gs:[0x2e0], rsp ; Win10 TEB InstrumentationCallbackPreviousSp
    mov gs:[0x2d8], r10 ; Win10 TEB InstrumentationCallbackPreviousPc
	
	mov r10, rcx ; save rcx
	sub rsp, 0x4d0 ; CONTEXT structure size
	and rsp, -16 ; align rsp
	mov rcx, rsp ; rsp to 1st param
	call RtlCaptureContext ; capture the thread's context
	
	sub rsp, 32 ; shadow stack
	call Hooker ; call and hopefully not int 3
	
	int 3 ; if this happens its ggs

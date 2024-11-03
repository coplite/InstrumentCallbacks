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
	mov rcx, rsp ; rsp to first param
	call RtlCaptureContext ; capture the thread's context
	
	sub rsp, 32 ; shadow stack space
	call Hooker ; call our func
	
	int 3 ; we should not be here.

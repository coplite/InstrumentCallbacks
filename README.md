# This is a simple PoC of instrumentation callback

Simple PoC of using instrument callbacks to detect direct syscalls

-: if you want to extend this functionality to indirect syscalls you can 
either use StackWalk64() or hook every syscall that increments a global
counter 

You can use it for injection by setting the callback on external process which points shellcode that same remote process

refs: idk i pulled ts outta my rear end :p

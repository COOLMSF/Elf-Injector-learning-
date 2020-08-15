section .text
        global _start

_start:
        mov rax,1       ; [1] - sys_write
        mov rdi,1       ; 0 = stdin / 1 = stdout / 2 = stderr
        lea rsi,[rel msg]     ; pointer(mem address) to msg (*char[])
        mov rdx, msg_end - msg      ; msg size
        syscall         ; calls the function stored in rax

;	mov rax,8
;	ret 
	mov rax, 0x1050
	jmp rax

align 8
        msg     db 'This file has been infected for 0x00SEC',0x0a,0
	msg_end db 0x0

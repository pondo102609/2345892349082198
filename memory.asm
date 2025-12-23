.code

ntreadvirtualmemory PROC
	mov r10, rcx
	mov eax, 63
	syscall
	ret
ntreadvirtualmemory ENDP

END
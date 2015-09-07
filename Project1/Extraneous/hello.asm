[SECTION .text]

global _start

_start:
	
	jmp short ender

	starter:

	xor eax, eax
	xor ebx, ebx
	xor edx, edx
	xor ecx, ecx

	mov al, 4
	mov bl, 1
	pop ecx
	mov dl, 5
	int 0x80

	xor eax, eax
	mov al, 1
	xor ebx, ebx
	int 0x80

	ender:
	call starter
	db 'hello'
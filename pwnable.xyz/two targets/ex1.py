from pwn import *

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)

def change_name(name):
	sla('>','1')
	sa(':',name)

def change_national(nation):
	sla('>','2')
	sa(':',nation)

def change_age(age):
	sla('>','3')
	sla(':',str(age))


if __name__ == '__main__':
	#context.log_level = 'debug'
	e = ELF('./challenge')
	#p = process('./challenge')
	p = remote('svc.pwnable.xyz',30031)

	s2 = [0x11, 0xDE, 0xCF, 0x10, 0xDF, 0x75, 0xBB, 0xA5, 0x43, 0x1E, 0x9D, 0xC2, 0xE3, 0xBF, 0xF5, 0xD6, 0x96, 0x7F, 0xBE, 0xB0, 0xBF, 0xB7, 0x96, 0x1D, 0xA8, 0xBB, 0x0A, 0xD9, 0xBF, 0xC9, 0x0D, 0xFF, 0x00]
	main_opcode = [85, 72, 137, 229, 72, 131, 236, 80, 100, 72, 139, 4, 37, 40, 0, 0, 0, 72, 137, 69, 248, 49, 192, 232, 36, 254, 255, 255, 72, 141, 69, 192]
	flag = ''
	for i in range(32):
		for j in range(256):
			if ((((j >> 4) | (j << 4)) ^ main_opcode[i]) & 0xff) == s2[i]:
				flag += chr(j)
				break
	log.info('check : ' + flag)
	change_name(flag)
	sla('>','4')

	p.interactive()
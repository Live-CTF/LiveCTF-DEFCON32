#!/usr/bin/env python3

from pwn import *
import json
import hashlib

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, PORT)

io.sendlineafter('> ', '5')
io.recvuntil('submitter\n')

pubkey = json.loads(io.recvline().split(b'\n')[0])

print(pubkey)
original = b'ls'
want = b'./submitter'

hash_int = int(hashlib.sha256(want).hexdigest(), 16)

n = pubkey['n']
cipher = pubkey['ctxt']

n2 = n * n

originalint = int.from_bytes(original, byteorder='big')
wantint = int.from_bytes(want, byteorder='big')

exponent = pow(originalint, -1, n) * wantint
ctxt = pow(cipher, exponent, n2)

pubkey = {
        'hash': hash_int,
        'ctxt': ctxt,
        'n': n
        }

io.sendlineafter(b'> ', b'4'+json.dumps(pubkey).encode())

flag = io.recvline().split(b'\n')[0].decode().strip()
log.info('Flag: %s', flag)
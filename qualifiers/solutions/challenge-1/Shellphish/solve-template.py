#!/usr/bin/env python3

import json
import random

from pwn import *
from hashlib import sha256

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


io = remote(HOST, PORT)
io.sendlineafter(b'> ', b'5')

io.recvuntil(b'{')
data = json.loads('{' + io.recvline().decode())
n = data.get('n')
h = data.get('hash')
ls_ctxt = data.get('ctxt')

assert int(sha256(b'ls').hexdigest(), 16) == h

base = int(b'ls'.hex(), 16)
N = 10

while True:
    tar = b"/bin/sh -c './submitter' #" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N)).encode()
    U = int(tar.hex(),16)
    if U % base == 0:
        break

k = U // base
ctxt = pow(ls_ctxt, k, n ** 2)
plain_hash = int(hashlib.sha256(tar).hexdigest(), 16)

to_send = '4' + json.dumps({'hash': plain_hash, 'ctxt': ctxt}).replace(' ', '')

io.sendlineafter(b'> ', to_send.encode())
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

#!/usr/bin/env python3
import json
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
print(io.recvuntil(b'>'))
io.sendline(b'5')

da = io.recvuntil(b'}').split(b'{')
da = da[-1]
js = json.loads('{' + da.decode())
ptxt = b'ls'

cmd = b'./submitter ;aAgb'
h = int(hashlib.sha256(cmd).hexdigest(), 16)
assert int.from_bytes(cmd, 'big') % int.from_bytes(ptxt, 'big') == 0
ctxt = pow(js['ctxt'], int.from_bytes(cmd, 'big') // int.from_bytes(ptxt, 'big'), js['n'] ** 2)

io.recvuntil(b'>')
io.sendline(b'4 ' + json.dumps({'hash': h, 'ctxt': ctxt, 'n': js['n']}).encode())

flag = io.recvline_contains(b'LiveCTF{').decode().strip()

log.info('Flag: %s', flag)
io.interactive()

#!/usr/bin/env python3

from pwn import *
import json
import hashlib
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io.interactive()
io.sendline(b'5')
io.recvuntil(b'{')

msg = b'{' + io.recvuntil(b'}')
msg = json.loads(msg)
n = msg['n']
ctxt = msg['ctxt']
ls = 27763
rls = pow(ls, -1, n)
print(rls)
ans = pow(ctxt,rls*29544,n**2)
h = int(hashlib.sha256(b'sh').hexdigest(), 16)
# print(msg)
io.sendline(b'4 ' + b'{"hash":%d,"ctxt":%d}' % (h, ans))
# io.interactive()
io.sendline(b'ls')
io.sendline(b'./submitter')
io.sendline(b'./submitter')
print(io.recvallS(timeout=3))
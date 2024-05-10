#!/usr/bin/env python3

from pwn import *
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

t= remote(HOST, int(PORT))
t.recvuntil(b">")
t.sendline(b"5")
t.recvuntil(b"{")
r=t.recvuntil(b"}").decode().strip(" \n{}")
r="{"+r+"}"
#print(f"{r=}")
r=json.loads(r)
n = r["n"]
ctxt = r["ctxt"]

new = pow(ctxt,8637685996160371807332146626880,n*n)
newhash = 0xd6971a9601dc94a08ceb0cfe1726757a9dde367c3eb898931dd1ad9e3ac09827
newjson = {"n":n,"ctxt":new,"hash":newhash}

t= remote(HOST, int(PORT))
t.recvuntil(b">")
t.sendline(b"4 "+json.dumps(newjson).encode())
print(t.recvall(timeout=3))
#t.interactive()


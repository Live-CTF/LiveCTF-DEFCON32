#!/usr/bin/env python3

from pwn import *
import json
from math import gcd, lcm
import hashlib

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))

p.recv()
p.sendline(b"5")
p.recvuntil(b"submitter\n")
data = p.recvuntil(b"\nWelcome")[:-8]
data = json.loads(data.decode())
ctxt, n = int(data["ctxt"]), int(data["n"])
n_sq = n**2
command = b'./submitter  ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;###############################################################################'
s, l = 153157960081366748454787986098846735241927187347448244834882348287476302220480052577222936773219994773537603119174918169746428272553455080651126906698170476179477206997682186204164563499174994048349519634288635516949604477171927681647410944625654431674572936285205264692622539927683678536713085283813695134195713125662659881149219, 27763
mult = s // l
ctxt2 = pow(ctxt, mult, n_sq)
h2 = int(hashlib.sha256(command).hexdigest(), 16)
msg2 = {'hash': h2, 'ctxt': ctxt2, 'n': n}

p.sendline(f'4 {json.dumps(msg2)}'.encode())
p.recvuntil(b"Leave\n> ")
print(p.recv().decode())

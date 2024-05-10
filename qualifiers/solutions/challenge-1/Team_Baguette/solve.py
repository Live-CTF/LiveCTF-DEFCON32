#!/usr/bin/env python3

from pwn import *
import json
import hashlib

"""
b'Welcome to Shiny Shell Hut!\\n1. View wares\\n2. Get a shiny shell\\n3. Leave\\n> backdoor.py\\nchallenge\\nkey.json\\nnsjail.conf\\nrun.sh\\nsubmitter\\n{\"hash\": 90332780745442119779253857231558597566447620910226630319466684469499960556217, \"ctxt\": 39441236018492732843679075380452340401136974591203481423177611496954251330650764648646529027162482952216236443085730308639018996825876986761860861526528406478337459424293336880331... 
"""


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

io.recvuntil(b">")
io.sendline(f"5".encode())

io.recvuntil(b"submitter\n")
out = json.loads(io.recvline())

m1 = int.from_bytes(b"ls", "big")
c1 = out["ctxt"]
n = out["n"]

ptxt = b"./submitter"
m3 = int.from_bytes(ptxt, "big")
m2 = (m3 * pow(m1, -1, n)) % n
c3 = pow(c1, m2, n**2)

payload = {
  "hash": int(hashlib.sha256(ptxt).hexdigest(), 16),
  "ctxt": c3,
  "n": n,
}

# print(payload)

io.sendline(f"4{json.dumps(payload)}".encode())

print(io.recvall())

io.close()

#!/usr/bin/env python3

from pwn import *

import json
import hashlib

HOST = os.environ.get("HOST", "localhost")
PORT = 31337
CMD = b"./submitter     "

k = int.from_bytes(CMD, "big") // int.from_bytes(b"ls", "big")
actual_ctxt = (k * int.from_bytes(b"ls", "big")).to_bytes(128, "big").lstrip(b"\x00")
print(actual_ctxt)
assert actual_ctxt.startswith(b"./submitter")

r = remote(HOST, int(PORT))

r.sendlineafter(b"> ", b"5")
r.recvuntil(b"{")
msg = json.loads(b"{" + r.recvuntil(b"}"))
N = msg["n"]
KNOWN_GOOD_CTXT = msg["ctxt"]

payload = {
    "hash": int(hashlib.sha256(actual_ctxt).hexdigest(), 16),
    "ctxt": pow(KNOWN_GOOD_CTXT, k, N**2),
}
r.sendline(b"4" + json.dumps(payload).encode())
# r.sendline(b"./submitter; exit")
print(r.recvall())

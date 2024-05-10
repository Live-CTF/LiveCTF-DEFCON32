from pwn import *

import json
import os
import hashlib
import re

context.log_level = "error"

json_re = re.compile(r"(\{.+\})")

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

# io.sendlineafter(b"> ", b"4" + message.encode())
io.sendlineafter(b"> ", b"5")
first_out = io.recvuntilS(b"> ")

# extract params
json_str = json_re.search(first_out).group(1)
json_obj = json.loads(json_str)
ls_ctxt = json_obj["ctxt"]
n = json_obj["n"]
n_2 = pow(n, 2)

# contains arg
submitter_ctxt = pow(ls_ctxt, 566079389444366126765319561340610645, n_2)

submitter_ptxt = b"./submitter aaa\xba/"
submitter_hash = int(hashlib.sha256(submitter_ptxt).hexdigest(), 16)

submitter_obj = {
    "hash": submitter_hash,
    "ctxt": submitter_ctxt,
    "n": n
}

submitter_str = json.dumps(submitter_obj)

io.sendline(b"4" + submitter_str.encode())

print(io.recvall())
#io.interactive()

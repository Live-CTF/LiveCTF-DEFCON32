import os
import json
import hashlib
from pwn import remote, log, context

context.log_level = "DEBUG"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))

io.sendlineafter(b"> ", b"5")
res = io.recvline().strip().decode()
log.info(res)
res = io.recvline().strip().decode()
log.info(res)
io.recvuntil(b"{")
res = "{" + io.recvline().strip().decode()
res = json.loads(res)
ctxt = res["ctxt"]
n = res["n"]

m = 8637685996160371807332146626811
ls = 27763
submitter = 3659180851919561805526159466555
L = 2
assert submitter * 256**L + 5313 == ls * m
ctxt_pwn = pow(ctxt, m, n**2)
cmd = b'./submitter ;\x14\xc1'
ptxt_pwn = int(hashlib.sha256(cmd).hexdigest(), 16)

io.sendlineafter(b"> ", f'4{{"hash":{ptxt_pwn},"ctxt":{ctxt_pwn}}}'.encode())
# flag = io.recvline_contains(b'LiveCTF{').decode().strip()
flag = io.recvall()
log.info('Flag: %s', flag)

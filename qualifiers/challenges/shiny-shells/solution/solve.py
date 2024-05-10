import hashlib
import json

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))

r.recvuntil(b'> ')
r.sendline(b'5')
r.recvuntil(b'{')
data = json.loads(b'{' + r.recvuntil(b'}'))

ptxt_hash = data["hash"]
ctxt = data["ctxt"]
n = data["n"]
n_sq = n*n

ptxt = b'ls'
assert int(hashlib.sha256(ptxt).hexdigest(), 16) == ptxt_hash
ptxt_int = int.from_bytes(ptxt)

command = b'./submitter'

# find x s.t. ptxt_int * x == 1 mod n
#   D(E(ptxt_int, r)**x) mod n**2 = ptxt_int*x mod n == 1 mod n
#   Then, for any 0 < y < n we can compute D((E(ptxt_int, r)**x)**y mod n**2) == 1*y mod n == y mod n == y

x = pow(ptxt_int, -1, n)
assert x < n

command_int = int.from_bytes(command)
command_ctxt = pow(pow(ctxt, x, n_sq), command_int, n_sq)
command_hash = int(hashlib.sha256(command).hexdigest(), 16)


payload = json.dumps({
    'hash': command_hash,
    'ctxt': command_ctxt,
    'n': n
}).encode()


r.recvuntil(b'> ')
r.sendline(b'4' + payload)


time.sleep(2)

r.sendline(b"./submitter")
r.recvuntil(b"Flag: ")
print(r.recvuntil(b"\n").decode(), end='')


r.interactive()

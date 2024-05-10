from pwn import *
import json

var = os.getenv("DEBUGINFOD_URLS")

binary_name = "challenge"
# exe  = ELF(binary_name, checksec=True)
# context.binary = exe

ru  = lambda *x: r.recvuntil(*x)
rl  = lambda *x: r.recvline(*x)
rc  = lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa  = lambda *x: r.sendafter(*x)
sl  = lambda *x: r.sendline(*x)
sn  = lambda *x: r.send(*x)

if var is None:
    HOST = os.environ.get("HOST", "localhost")
    PORT = 31337
    r = connect(HOST, int(PORT))
elif args.GDB:
    r = gdb.debug(f"./{binary_name}", """
        c
    """, aslr=False)
else:
    r = process(f"./{binary_name}")


sla(b"> ", b"5")
ru(b"{")
ln = b"{" + rl().strip()
print(ln)
data = json.loads(ln.decode())

import hashlib

ctxt = data["ctxt"]
n = data["n"]
plaintext = b'ls'
inv = pow(int.from_bytes(b'ls', byteorder="big"), -1, n) 

target = b'./submitter'
enc = pow(ctxt, (int.from_bytes(target, byteorder="big") * inv) % n, n**2)
hash_final = int(hashlib.sha256(target).hexdigest(), 16)
out = dict()
out["hash"] = hash_final
out["ctxt"] = enc
out["n"] = n


tosend = b"4" + json.dumps(out).encode()
sla(b"> ", tosend)



# r.interactive()
# after shell xd
# r.sendline(b'./submitter')
print(r.recvall(timeout=1))

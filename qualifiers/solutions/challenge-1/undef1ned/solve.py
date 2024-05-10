from pwn import *
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def get_ls():
    r.sendlineafter(b"> ", b"5")
    while True:
      hoge = r.recvline().decode()
      if '"n"' in hoge: return json.loads(hoge)

def send_cmd(hash, ctxt):
    msg = {"hash": hash, "ctxt": ctxt} # solve me

    payload = b"4" + json.dumps(msg).encode()
    r.sendlineafter(b"> ", payload)

#r = process("./challenge", cwd="../handout")
r = remote(HOST, int(PORT))

res = get_ls()
_, ctxt_ls, n = res['hash'], res['ctxt'], res['n']

req = b"./submitter"
req_int = int.from_bytes(req, 'big')
req_hash = int(hashlib.sha256(req).hexdigest(), 16)

inv = pow(27763, -1, n * n)
my_ctxt = pow(ctxt_ls, inv * req_int, n * n)
send_cmd(req_hash, my_ctxt)

print(r.recvall().decode())

r.close()
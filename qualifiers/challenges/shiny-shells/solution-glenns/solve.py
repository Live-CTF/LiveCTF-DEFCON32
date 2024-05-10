import json
import hashlib
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, PORT)

r.recvuntil(b'> ')
r.sendline(b'5')
r.recvuntil(b'{')
conts = json.loads(b'{' + r.recvuntil(b'}'))


hash = conts['hash']
ctxt = conts['ctxt']
n = conts['n']
# g = n + 1

def do_hash(ptxt_int):
    ptxt_hex = format(ptxt_int, 'x')
    if len(ptxt_hex) % 2:
        ptxt_hex = '0' + ptxt_hex
    ptxt = bytes.fromhex(ptxt_hex)
    return int(hashlib.sha256(ptxt).hexdigest(), 16)

def str_int(ptxt):
    result = 0
    for ch in ptxt:
        result <<= 8
        result |= ord(ch)
    return result

def int_str(ptxt_int):
    ptxt_hex = format(ptxt_int, 'x')
    if len(ptxt_hex) % 2:
        ptxt_hex = '0' + ptxt_hex
    return bytes.fromhex(ptxt_hex)

# don't have g so we cant enc directly
# but we _can_ add b'ls' to b'ls' until it gives a number that starts with our payload

msg = 'ls'
msg_int = str_int(msg)

target_int = str_int('sh -c sh    ')
target = hex(target_int)

print(f'msg_int={msg_int:x}')
print(f'target_int={target_int:x}')

nn = target_int // msg_int

print(f'nn={nn}')

def pai_add(a, b, n):
    return (a * b) % (n**2)

# is there a better way to do this? of course
# did i do that? of course not
ctxt1000 = ctxt
for i in range(1, 1000):
    ctxt1000 = pai_add(ctxt1000, ctxt, n)
ctxt1000000 = ctxt1000
for i in range(1, 1000):
    ctxt1000000 = pai_add(ctxt1000000, ctxt1000, n)
ctxt1000000000 = ctxt1000000
for i in range(1, 1000):
    ctxt1000000000 = pai_add(ctxt1000000000, ctxt1000000, n)
ctxt1000000000000 = ctxt1000000000
for i in range(1, 1000):
    ctxt1000000000000 = pai_add(ctxt1000000000000, ctxt1000000000, n)
ctxt1000000000000000 = ctxt1000000000000
for i in range(1, 1000):
    ctxt1000000000000000 = pai_add(ctxt1000000000000000, ctxt1000000000000, n)
ctxt1000000000000000000 = ctxt1000000000000000
for i in range(1, 1000):
    ctxt1000000000000000000 = pai_add(ctxt1000000000000000000, ctxt1000000000000000, n)
ctxt1000000000000000000000 = ctxt1000000000000000000
for i in range(1, 1000):
    ctxt1000000000000000000000 = pai_add(ctxt1000000000000000000000, ctxt1000000000000000000, n)
ctxt1000000000000000000000000 = ctxt1000000000000000000000
for i in range(1, 1000):
    ctxt1000000000000000000000000 = pai_add(ctxt1000000000000000000000000, ctxt1000000000000000000000, n)
# this section brought to you by copy paste more times than i thought was necessary
#nn=1286484038744673680191560
ctxt1000000000000000000000000000 = ctxt1000000000000000000000000
for i in range(1, 1000):
    ctxt1000000000000000000000000000 = pai_add(ctxt1000000000000000000000000000, ctxt1000000000000000000000000, n)

result = 1
for i in range((nn % 1000000000000000000000000000)//1000000000000000000000000):
    result = pai_add(result, ctxt1000000000000000000000000, n)
for i in range((nn % 1000000000000000000000000)//1000000000000000000000):
    result = pai_add(result, ctxt1000000000000000000000, n)
for i in range((nn % 1000000000000000000000)//1000000000000000000):
    result = pai_add(result, ctxt1000000000000000000, n)
for i in range((nn % 1000000000000000000)//1000000000000000):
    result = pai_add(result, ctxt1000000000000000, n)
for i in range((nn % 1000000000000000)//1000000000000):
    result = pai_add(result, ctxt1000000000000, n)
for i in range((nn % 1000000000000)//1000000000):
    result = pai_add(result, ctxt1000000000, n)
for i in range((nn % 1000000000)//1000000):
    result = pai_add(result, ctxt1000000, n)
for i in range((nn % 1000000)//1000):
    result = pai_add(result, ctxt1000, n)
for i in range(nn % 1000):
    result = pai_add(result, ctxt, n)

print(int_str(str_int('ls')* nn))
conts['ctxt'] = result
conts['hash'] = do_hash(str_int('ls')*nn)

print(f"conts={json.dumps(conts)}")
r.sendlineafter(b"> ", f"4 {json.dumps(conts)}".encode())

r.sendline(b"./submitter")
print(r.recvuntil(b"Flag: ").decode(), end='')
print(r.recvuntil(b"\n").decode(), end='')

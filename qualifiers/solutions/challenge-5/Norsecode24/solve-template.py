#!/usr/bin/env python3

from pwn import *
import hashlib


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


import angr
# def solve():
#     p = angr.Project("crackme", main_opts={
#         'base_addr': 0x0,
#     })
#     init_st = p.factory.entry_state(add_options=angr.options.unicorn)
#     sm = p.factory.simgr(init_st)
#     sm.use_technique(angr.exploration_techniques.DFS())
#     sm.explore(find=lambda s: b"Success" in s.posix.dumps(1), avoid=lambda s: b"Fail" in s.posix.dumps(1))
#     #print(sm)
#     #print(sm.found)
#     #for f in sm.found:
#     #    x = f.posix.dumps(0)
#     #    print(x, x.hex())
#     return sm.found[0].posix.dumps(0)
import claripy
def solve(filename="crackme"):
    import logging
    logging.getLogger('angr').setLevel('ERROR')
    import angr
    p = angr.Project(filename, main_opts={
        'base_addr': 0x0,
    })

    inp = claripy.BVS('inp', 9*8)

    init_st = p.factory.entry_state(
        add_options=angr.options.unicorn,
        stdin=inp,
    )
    for byte in inp.chop(8)[:-1]:
        init_st.add_constraints(byte >= ord('0'))
        init_st.add_constraints(byte <= ord('z'))
    init_st.add_constraints(inp.chop(8)[-1] == 0x0a)

    sm = p.factory.simgr(init_st)
    sm.use_technique(angr.exploration_techniques.DFS())
    sm.explore(find=lambda s: b"Success" in s.posix.dumps(1), avoid=lambda s: b"Fail" in s.posix.dumps(1))
    #print(sm)
    #print(sm.found)
    #for f in sm.found:
    #    x = f.posix.dumps(0)
    #    print(x, x.hex())
    return sm.found[0].posix.dumps(0)

io = remote(HOST, int(PORT))
for i in range(5):
    print(io.recvuntil(b'File: '))

    file = base64.decodebytes(io.recvline())
    Path("crackme").write_bytes(file)
    ans = solve()
    print(ans)
    io.send(ans)
    print(io.recvline())
io.sendline(b"./submitter")
res = io.recvall(1)
print(res)
#!/usr/bin/env python3

import base64
from pwn import *
from concurrent.futures import ThreadPoolExecutor
import os
import time

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

io = remote(HOST, int(PORT))


def trial(flag_str):
    p = os.popen(
        f"echo {flag_str} | valgrind --tool=callgrind ./1.bin 2>&1|grep refs; rm -rf callgrind.out*",
        "r",
    )
    data = p.read().strip()
    data = int(data.split(" ")[-1].replace(",", ""))
    p.close()
    return flag_str, data

for i in range(5):
    io.recvuntil(b"File: ")
    binary = base64.b64decode(io.recvline())
    open("1.bin", "wb").write(binary)
    os.chmod("1.bin", 0o755)

    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    flag = list("01234567")
    for j in range(8):
        thread_pool = ThreadPoolExecutor(max_workers=8)
        maximum = ""
        candidates = []
        for c in charset:
            flag[j] = c
            flag_str = "".join(flag)
            candidates.append(flag_str)
        variance = set()
        max_str = ""
        for flag_str, data in thread_pool.map(trial, candidates):
            if not variance or max(variance) < data:
                max_str = flag_str
            variance.add(data)
        print(max_str)
        flag = list(max_str)

    io.sendline(''.join(flag).encode())

io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

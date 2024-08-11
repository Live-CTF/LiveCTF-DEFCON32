import argparse
from datetime import datetime
import sys

from pwn import *

debug = False

context.log_level = 'debug' if debug else 'info'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8000", help="Address of challenge")


args = parser.parse_args()

HOST, PORT = args.address.split(':')

# https://gist.github.com/integeruser/4cca768836c68751904fe215c94e914c
# http://www.mscs.dal.ca/~selinger/random/
from ctypes import c_int, c_uint
def srand(seed):
    state = {}
    state["r"] = [0 for _ in range(34)]
    state["r"][0] = c_int(seed).value
    for i in range(1, 31):
        state["r"][i] = (16807 * state["r"][i - 1]) % 2147483647
    for i in range(31, 34):
        state["r"][i] = state["r"][i - 31]
    state["k"] = 0
    for _ in range(34, 344):
        rand(state)
    return state


def rand(state):
    state["r"][state["k"]] = state["r"][(state["k"] - 31) %
                               34] + state["r"][(state["k"] - 3) % 34]
    r = c_uint(state["r"][state["k"]]).value >> 1
    state["k"] = (state["k"] + 1) % 34
    return r, state


r = remote(HOST, int(PORT))
start_now = int(datetime.now().timestamp())

# Over engineered time(0) guessing
for i in range(1):
    for j in range(10):
        try:
            time = start_now + (j-4)
            print(time)
            state = srand(time)

            for x in range(j+1):
                a, state = rand(state)
                b, state = rand(state)

            print(f"{a:x} * {b:x} == {a*b:x}")

            r.sendlineafter(b"What's the answer:\n", hex(a * b)[2:].encode())

            line = r.recvline()
            if line == b"Yes! That's it!\n":
                r.interactive()
                sys.exit(0)

            print(line)
            line = r.recvline()
            print(line)
        except AssertionError:
            pass
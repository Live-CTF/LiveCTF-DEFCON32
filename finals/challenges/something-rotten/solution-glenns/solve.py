import argparse

from pwn import *

debug = True

context.log_level = 'debug' if debug else 'info'
context.terminal = ['tmux', 'splitw', '-v']
context.arch = 'amd64'

network = len(sys.argv) > 1

parser = argparse.ArgumentParser()
default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
parser.add_argument("--network", action='store_true')
parser.add_argument("address", default=default_addr,
                    nargs="?", help="Address of challenge")
args = parser.parse_args()
HOST, PORT = args.address.split(':')

r = remote(HOST, int(PORT))

r.sendlineafter(b"Flag:", b"LiveCTF{th4ts_qUit3_th3_p1ckle}")

r.interactive()

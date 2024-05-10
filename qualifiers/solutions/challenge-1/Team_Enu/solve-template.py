#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

# io.send(b"4\n")

import json

# print("try message.json")
# io.send('4{"hash": 90332780745442119779253857231558597566447620910226630319466684469499960556217,"ctxt": 73051477874175319898927301574056890898704116542880899811855416465272643682482346872783064596681132500093342543927350264317816705056726017562052386926181322166187767850184465510257796954957460330077783876352326207867696650111732540101368587373210436484887313543491225210356125240581684161338044619494047854900183079330422962318329546393970108675111208668731515310810119669669785116258853775579596914067264319604960692189737974799003960161097925809658756864172165995060221657693350799455527766362031052645281448993284426009064500366073322116732260765304288850209892843144957962916560778212599399552579286945076904181402045509524352633967429874194201741806721664196445347759142097532829953125517498551062761903031892701576548444435244611198108640987159546381903097946809287365052398012455687453466700260273341554786191027926777189035233725939692111334381040651927022112173802116643713729121047574308803077213575536485741502404927006914803136414467058642884171002528878169339845622793977402503234182588769709154961649934730828326538949645182926356414533497836632833727562183129066423778578583057064315858610392480954433559213008717680626378247498277787414520519791236257431556708009843017374097633810653489799748754465484619328171001827}\n'.encode())
print("try 5")
io.send('5\n'.encode())
io.recvuntil(b"{\"hash\"")
res = json.loads((b"{\"hash\""+io.recvuntil(b"\n")).decode())
print(f"{res=}")

print("try attack")
ptxt = b"./submitter \x3d\x33"
import hashlib
h = int(hashlib.sha256(ptxt).hexdigest(), 16)
ptxt_ls = int(ptxt.hex(), 16)//int(b"ls".hex(), 16)
assert int(ptxt.hex(), 16)%int(b"ls".hex(), 16) == 0
n = res["n"]
ctxt = pow(res["ctxt"], ptxt_ls, n*n)
payload = json.dumps({"hash": h, "ctxt": ctxt})
io.send(('4'+payload+'\n').encode())

for _ in range(25):
  print(io.recvuntil(b"\n"))
# io.interactive()

#!/usr/bin/env python3

import arc4
import pickletools
import pickle
import random
import struct
from pathlib import Path
from Crypto.Protocol.KDF import PBKDF2


class SlotCounter:
    def __init__(self, base):
        self.counter = base

    def get1(self):
        res = self.counter
        self.counter += 1
        resbytes = struct.pack("<B", res & 0xFF)
        return resbytes

    def get4(self):
        res = self.counter
        self.counter += 1
        resbytes = struct.pack("<I", res & 0xFFFFFFFF)
        return resbytes


"""
Globals table
0: password
1: ord()
2: 
"""
globals_toc = {
    ('builtins', 'ord'): 1,
    ('operator', 'eq'): 2,
    ('operator', 'xor'): 3,
    ('operator', 'add'): 4,
    ('operator', 'sub'): 5,
    ('operator', 'mul'): 6,
    ('operator', 'itemgetter'): 7,
    ('builtins', 'id'): 8,
    ('sys', 'exit'): 9,
}

# operator.attrgetter
# operator.attrgetter, 'password'
# operator.attrgetter, ('password',)
# operator.attrgetter('password')
# operator.attrgetter('password'), builtins.globals
# operator.attrgetter('password'), builtins.globals, ()
# operator.attrgetter('password'), __globals__
# operator.attrgetter('password'), (__globals__,)
# password
# memory[0] = password
def get_password():
    return [
        # push operator.itemgetter
        pickle.BINGET,
        bytes([globals_toc[('operator', 'itemgetter')]]),
        # operator.attrgetter('password')
        pickle.STRING,
        b"'password'\n",
        pickle.TUPLE1,
        pickle.REDUCE,
        # GLOBAL builtins.globals
        pickle.GLOBAL,
        b"builtins\n",
        b"globals\n",
        # globals()
        pickle.EMPTY_TUPLE,
        pickle.REDUCE,
        # globals()['password']
        pickle.TUPLE1,
        pickle.REDUCE,
        # memory[0] = password
        pickle.BINPUT,
        b"\0",
        pickle.POP,
    ]

def prepare_globals():
    result = []
    for (keya, keyb), idx in globals_toc.items():
        result += [
            # GLOBAL keya.keyb
            pickle.GLOBAL,
            (keya+'\n').encode(),
            (keyb+'\n').encode(),
            pickle.BINPUT,
            bytes([idx]),    
            pickle.POP,
        ]
    return result

# builtins.ord
# builtins.ord, operator.itemgetter
# builtins.ord, operator.itemgetter, idx
# builtins.ord, operator.itemgetter, (idx, )
# builtins.ord, operator.itemgetter(idx)
# builtins.ord, operator.itemgetter(idx), password
# builtins.ord, password[idx]
# ord(password[idx])
def get_password_char(idx):
    return [
        # push builtins.ord
        pickle.BINGET,
        bytes([globals_toc[('builtins', 'ord')]]),
        # push operator.itemgetter
        pickle.BINGET,
        bytes([globals_toc[('operator', 'itemgetter')]]),
        # operator.itemgetter(idx)
        pickle.BININT1,
        bytes([idx]),
        pickle.TUPLE1,
        pickle.REDUCE,
        # push memory[0] (password)
        pickle.BINGET,
        b"\0",
        # password[idx]
        pickle.TUPLE1,
        pickle.REDUCE,
        # ord(password[idx])
        pickle.TUPLE1,
        pickle.REDUCE,
    ]


# top
#
# operator.eq
# operator.eq, b
# operator.eq, b, operator.xor
# operator.eq, b, operator.xor, top
# operator.eq, b, operator.xor, top, a
# operator.eq, b, operator.xor, (top, a)
# operator.eq, b, top^a
# operator.eq, (b, top^a)
# b == top ^ a
def xor_and_check(slot_counter, a, b):
    b ^= a
    slot1 = slot_counter.get4()
    return [
        # memory[1] = top
        pickle.LONG_BINPUT,
        slot1,
        pickle.POP,
        # push operator.eq
        pickle.BINGET,
        bytes([globals_toc[('operator', 'eq')]]),
        # push B
        pickle.BININT,
        struct.pack("<i", b),
        # push operator.xor
        pickle.BINGET,
        bytes([globals_toc[('operator', 'xor')]]),
        # push memory[1]
        pickle.LONG_BINGET,
        slot1,
        # push A
        pickle.BININT,
        struct.pack("<i", a),
        # xor(top, a)
        pickle.TUPLE2,
        pickle.REDUCE,
        # eq(b, xor(top, a))
        pickle.TUPLE2,
        pickle.REDUCE,
    ]


# top
#
# operator.eq
# operator.eq, b
# operator.eq, b, operator.xor
# operator.eq, b, operator.xor, top
# operator.eq, b, operator.xor, top, a
# operator.eq, b, operator.xor, (top, a)
# operator.eq, b, top^a
# operator.eq, (b, top+a)
# b == top + a
def add_and_check(slot_counter, a, b):
    b += a
    slot1 = slot_counter.get4()
    return [
        # memory[1] = top
        pickle.LONG_BINPUT,
        slot1,
        pickle.POP,
        # push operator.eq
        pickle.BINGET,
        bytes([globals_toc[('operator', 'eq')]]),
        # push B
        pickle.BININT,
        struct.pack("<i", b),
        # push operator.add
        pickle.BINGET,
        bytes([globals_toc[('operator', 'add')]]),
        # push memory[1]
        pickle.LONG_BINGET,
        slot1,
        # push A
        pickle.BININT,
        struct.pack("<i", a),
        # add(top, a)
        pickle.TUPLE2,
        pickle.REDUCE,
        # eq(b, add(top, a))
        pickle.TUPLE2,
        pickle.REDUCE,
    ]


# top
#
# operator.eq
# operator.eq, b
# operator.eq, b, operator.xor
# operator.eq, b, operator.xor, top
# operator.eq, b, operator.xor, top, a
# operator.eq, b, operator.xor, (top, a)
# operator.eq, b, top^a
# operator.eq, (b, top*a)
# b == top * a
def mul_and_check(slot_counter, a, b):
    b *= a

    slot1 = slot_counter.get4()
    return [
        # memory[1] = top
        pickle.LONG_BINPUT,
        slot1,
        pickle.POP,
        # push operator.eq
        pickle.BINGET,
        bytes([globals_toc[('operator', 'eq')]]),
        # push B
        pickle.BININT,
        struct.pack("<i", b),
        # push operator.mul
        pickle.BINGET,
        bytes([globals_toc[('operator', 'mul')]]),
        # push memory[1]
        pickle.LONG_BINGET,
        slot1,
        # push A
        pickle.BININT,
        struct.pack("<i", a),
        # mul(top, a)
        pickle.TUPLE2,
        pickle.REDUCE,
        # eq(b, mul(top, a))
        pickle.TUPLE2,
        pickle.REDUCE,
    ]


# top
#
# operator.eq
# operator.eq, b
# operator.eq, b, operator.sub
# operator.eq, b, operator.sub, top
# operator.eq, b, operator.sub, top, a
# operator.eq, b, operator.sub, (top, a)
# operator.eq, b, top^a
# operator.eq, (b, top*a)
# b == top * a
def sub_and_check(slot_counter, a, b):
    b -= a

    slot1 = slot_counter.get4()
    return [
        # memory[1] = top
        pickle.LONG_BINPUT,
        slot1,
        pickle.POP,
        # push operator.eq
        pickle.BINGET,
        bytes([globals_toc[('operator', 'eq')]]),
        # push B
        pickle.BININT,
        struct.pack("<i", b),
        # push operator.sub
        pickle.BINGET,
        bytes([globals_toc[('operator', 'sub')]]),
        # push memory[1]
        pickle.LONG_BINGET,
        slot1,
        # push A
        pickle.BININT,
        struct.pack("<i", a),
        # mul(top, a)
        pickle.TUPLE2,
        pickle.REDUCE,
        # eq(b, mul(top, a))
        pickle.TUPLE2,
        pickle.REDUCE,
    ]

# top
#
# operator.itemgetter
# operator.itemgetter, top
# operator.itemgetter(top)
# operator.itemgetter(top), sys.exit
# operator.itemgetter(top), sys.exit, builtins.id
# operator.itemgetter(top), (sys.exit, builtins.id)
# sys.exit/builtins.id
# sys.exit/builtins.id, 1
# sys.exit/builtins.id, (1,)
# sys.exit/builtins.id(1)
def exit_if_false(slot_counter):
    slot1 = slot_counter.get4()
    return [
        # memory[1] = top
        pickle.LONG_BINPUT,
        slot1,
        pickle.POP,
        # push operator.itemgetter
        pickle.BINGET,
        bytes([globals_toc[('operator', 'itemgetter')]]),
        # push top
        pickle.LONG_BINGET,
        slot1,
        # operator.itemgetter(top)
        pickle.TUPLE1,
        pickle.REDUCE,
        # push sys.exit
        pickle.BINGET,
        bytes([globals_toc[('sys', 'exit')]]),
        # push builtins.id
        pickle.BINGET,
        bytes([globals_toc[('builtins', 'id')]]),
        pickle.TUPLE2,
        pickle.TUPLE1,
        pickle.REDUCE,
        # push 1
        pickle.BININT1,
        bytes([1]),
        pickle.TUPLE1,
        pickle.REDUCE,
        # FIX: function without result discard id(1)
        pickle.POP,
    ]


def epilogue(encrypted):
    return [
        # push encrypted_flag
        pickle.SHORT_BINBYTES,
        bytes([len(encrypted)]),
        encrypted,
        # STOP
        pickle.STOP,
    ]


slot_counter = SlotCounter(0x1000)


target_password = "w3_4re_jUsT_inNoc3nT_m3N"

flag = "LiveCTF{th4ts_qUit3_th3_p1ckle}".encode()
flag_hash = PBKDF2(flag, b"something-rotten-flag", count=10000)
rc4 = arc4.ARC4(target_password.encode())
encrypted_flag = rc4.encrypt(flag)


operations = [
    xor_and_check,
    add_and_check,
    mul_and_check,
    sub_and_check,
]


program = [
    prepare_globals(),
    get_password(),
]

for i, flag_v in enumerate(target_password.encode()):
    operation = random.choice(operations)
    modval = random.randint(0, 0xFF)
    program += [
        get_password_char(i),
        xor_and_check(slot_counter, modval, flag_v),
        exit_if_false(slot_counter),
    ]

program += [
    epilogue(encrypted_flag)
]

payload = b"".join(b"".join(part) for part in program)

password = target_password

pickletools.dis(payload)
res = pickle.loads(payload)
print(f"Result: {res}")

src_dir = Path(__file__).parent.parent

with open(src_dir / "src" / "challenge.tpl.py", "r") as fin:
    challenge_template = fin.read()
challenge_code = challenge_template % payload.hex()
challenge_output_path = src_dir / "build" / "challenge.py"
with open(challenge_output_path, "w") as fout:
    fout.write(challenge_code)
challenge_output_path.chmod(0o0755)

with open(src_dir / "src" / "server.tpl.py", "r") as fin:
    server_template = fin.read()
server_code = server_template.replace("FLAG_HASH_PLACEHOLDER", flag_hash.hex())
server_output_path = src_dir / "build" / "server.py"
with open(server_output_path, "w") as fout:
    fout.write(server_code)
server_output_path.chmod(0o0755)

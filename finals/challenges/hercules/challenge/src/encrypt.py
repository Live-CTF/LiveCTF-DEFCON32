#!/usr/bin/env python3

import string
import arc4
import itertools
import random
import struct
import sys
from pathlib import Path
from Crypto.Protocol.KDF import PBKDF2

base_name = sys.argv[1]
flag = sys.argv[2]
num_inputs = int(sys.argv[3])
size = int(sys.argv[4])

INT64_MAX = (1 << 64) - 1
INT32_MAX = (1 << 32) - 1
MAX_DIST = INT32_MAX
# MAX_DIST = 10

flag_hash = PBKDF2(flag, b"hercules-flag", count=10000)

template_c = """
#include <stdint.h>
#include "flag.h"
unsigned char flag_encrypted[FLAG_LEN] = {
    %s
};
char* inputs[2*NUM_INPUTS] = {
    %s
};
"""

template_h = """
#define NUM_INPUTS %d
#define FLAG_LEN %d
extern unsigned char flag_encrypted[FLAG_LEN];
extern char* inputs[2*NUM_INPUTS];
"""


def generate_input_strings(num_inputs, max_size):
    # ALPHABET = string.ascii_letters + string.digits
    ALPHABET = string.ascii_uppercase

    input_strings = [
        "".join(
            random.choice(ALPHABET)
            for _ in range(random.randint(max_size // 2, max_size))
        )
        for _ in range(2 * num_inputs)
    ]

    return input_strings


# From: https://python-course.eu/applications-python/levenshtein-distance.php
def iterative_levenshtein(s, t):
    """
    iterative_levenshtein(s, t) -> ldist
    ldist is the Levenshtein distance between the strings
    s and t.
    For all i and j, dist[i,j] will contain the Levenshtein
    distance between the first i characters of s and the
    first j characters of t
    """

    rows = len(s) + 1
    cols = len(t) + 1
    dist = [[0 for x in range(cols)] for x in range(rows)]

    # source prefixes can be transformed into empty strings
    # by deletions:
    for i in range(1, rows):
        dist[i][0] = i

    # target prefixes can be created from an empty source string
    # by inserting the characters
    for i in range(1, cols):
        dist[0][i] = i

    for col in range(1, cols):
        for row in range(1, rows):
            if s[row - 1] == t[col - 1]:
                cost = 0
            else:
                cost = 1
            dist[row][col] = min(
                dist[row - 1][col] + 1,  # deletion
                dist[row][col - 1] + 1,  # insertion
                dist[row - 1][col - 1] + cost,
            )  # substitution

    return dist[row][col]


def calculate_edit_distances(input_strings):
    assert len(input_strings) % 2 == 0, len(input_strings)

    result = []
    for i in range(0, len(input_strings), 2):
        string_a, string_b = input_strings[i], input_strings[i + 1]
        result.append(iterative_levenshtein(string_a, string_b))
    assert 2 * len(result) == len(input_strings)

    return result


input_strings = generate_input_strings(num_inputs, size)
input_strings_c = ",\n\t".join(f'"{x}"' for x in input_strings)
edit_distances = calculate_edit_distances(input_strings)

print(input_strings)

key = bytes(x & 0xFF for x in edit_distances)
print(f"RC4 key: {key.hex()}")
rc4 = arc4.ARC4(key)
ciphertext = rc4.encrypt(flag.encode() + b"\0")

code = template_c % (
    ", ".join(f"{x:#04x}" for x in ciphertext),
    input_strings_c,
)
header = template_h % (num_inputs, len(ciphertext))


with open(f"{base_name}.c", "w") as fout:
    fout.write(code)

with open(f"{base_name}.h", "w") as fout:
    fout.write(header)

src_dir = Path(__file__).parent.parent
with open(src_dir / "src" / "server.tpl.py", "r") as fin:
    server_template = fin.read()
server_code = server_template.replace("FLAG_HASH_PLACEHOLDER", flag_hash.hex())
output_path = src_dir / "build" / "server.py"
with open(output_path, "w") as fout:
    fout.write(server_code)
output_path.chmod(0o0755)

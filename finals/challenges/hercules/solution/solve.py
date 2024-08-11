import argparse
import itertools
import arc4

from pwn import *

ADDR_INPUTS = 0x5060
SIZE_PROBLEM = 32
ADDR_FLAG = 0x5020
SIZE_FLAG = 37

INT64_MAX = (1 << 64) - 1


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


def read_cstring(elf, addr):
    result = []
    while True:
        cur_byte = elf.read(addr, 1)[0]
        if cur_byte == 0:
            break
        result.append(cur_byte)
        addr += 1
    return bytes(result)


elf = ELF("../challenge/handout/challenge")

distance_pointers = struct.unpack(
    f"<{2*SIZE_PROBLEM}Q", elf.read(ADDR_INPUTS, 8 * SIZE_PROBLEM * 2)
)
flag_encrypted = elf.read(ADDR_FLAG, SIZE_FLAG)
input_strings = [read_cstring(elf, x) for x in distance_pointers]

edit_distances = calculate_edit_distances(input_strings)

key = bytes(x & 0xFF for x in edit_distances)
rc4 = arc4.ARC4(key)
flag_decrypted = rc4.decrypt(flag_encrypted)

log.info("Flag: %s", flag_decrypted.decode().strip("\0"))

parser = argparse.ArgumentParser()
parser.add_argument("address", default="127.0.0.1:8000", help="Address of challenge")
args = parser.parse_args()
HOST, PORT = args.address.split(":")
r = remote(HOST, int(PORT))

r.sendline(flag_decrypted.decode().strip("\0"))

r.interactive()

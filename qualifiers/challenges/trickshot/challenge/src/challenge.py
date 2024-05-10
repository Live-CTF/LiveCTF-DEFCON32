#!/usr/bin/python3

import os
import re
import subprocess
import sys


def main():

    print(f"Setting you up for a trickshot...")
    sys.stdout.flush()

    buffer = sys.stdin.buffer.read(1000)
    process = subprocess.Popen(
        ["./trickshot"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate(input=buffer, timeout=5)
    if process.returncode != 0:
        print("Error:", stderr.decode(), file=sys.stderr)

    output_str = stdout.decode()
    print(output_str)

    pattern = r"\+(\d+)"
    scores = re.findall(pattern, output_str)
    score = 0
    for cur_score in scores:
        score += int(cur_score)

    print(f"===== TRICKSHOT COMPLETE =====\n")
    print(f"Initial score: {score}")

    pattern = r"x(\d)"
    multiplier_matches = re.findall(pattern, output_str)
    print(f"You found {len(multiplier_matches)} score multipliers!")
    multiplier = 1
    for cur_score in multiplier_matches:
        multiplier *= int(cur_score)
    print(f"Total multiplier: {multiplier}x")
    score *= multiplier

    if len(multiplier_matches) > 4:
        quad_bonus_bonus = 600000
        print(f"You achieved the multi-bonus bonus!!!!!!")
        score += quad_bonus_bonus

    print(f"Final score: {score}")

    THRESHOLD = 640000
    if score >= THRESHOLD:
        # with open('flag') as f:
        #    data = f.read()
        #    print(data)
        # os.system('./submitter')
        os.system("/bin/sh")
    else:
        print(f"I know you can do better!")


if __name__ == "__main__":
    main()

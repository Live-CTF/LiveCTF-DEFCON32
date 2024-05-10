import subprocess
import random
import string

from pathlib import Path

try:
    import binaryninja
except:
    print("This script requires Binary Ninja to be in the python path")

NUM_BINS = 20

OUT_BIN_DIR = Path('bins')
OUT_GENERATED_DIR = Path('generated')

OUT_BIN_DIR.mkdir(exist_ok=True)
OUT_GENERATED_DIR.mkdir(exist_ok=True)

#scc = "/Applications/Binary Ninja-2.0.app/Contents/MacOS/plugins/scc"
scc = "/home/josh/Downloads/binaryninja/plugins/scc"

possible_checks = [
    'check_lower(%s)',
    'check_upper(%s)',
    'check_digit(%s)',
    'check_digit_gt(%s, %s)',
    'check_prime(%s)',
    'check_not_in_str(%s, "%s")',
    'check_between(%s, \'%s\', \'%s\')',
]

def generate_checks() -> list[str]:
    checks = []
    for idx in range(8):
        check = random.choice(possible_checks)
        if check.count('%s') == 1:
            check = check % f'input[{idx}]'
        elif check.startswith('check_digit_gt'):
            check = check % (f'input[{idx}]', str(random.randint(0,8)))
        elif check.startswith('check_not_in_str'):
            check = check % (f'input[{idx}]', ''.join(random.sample(string.ascii_letters, k=len(string.ascii_letters)-3)))
        elif check.startswith('check_between'):
            lower = random.randint(0,6)
            upper = random.randint(lower+1,9)
            check = check % (f'input[{idx}]', str(lower), str(upper))
        else:
            raise Exception("unhandled check")
        checks.append(check)
        checks.append("for (int i = 0; i < 10; i++) { }")
    return checks

template = open("challenge_template.c", 'r').read()

for challenge_number in range(NUM_BINS):
    generated_file = OUT_GENERATED_DIR / f'challenge_generated_{challenge_number}.c'

    with open(generated_file, 'w') as out:
        filled_template = template.replace('REPLACEME', '\n'.join(generate_checks()))
        out.write(filled_template)

    print(f"Compiling {generated_file} using {scc}")

    subprocess.run([scc, "--arch", "quark", "-m32", "-o", "quark.bin", generated_file])
    data = open("quark.bin", "rb").read()
    blob = binaryninja.Transform['StringEscape'].encode(data)
    assert blob is not None

    source = 'void main()\n{\nchar *quarkbin = "' + blob.decode('utf-8') + '";\nquark_exec(quarkbin);\n}'

    with open('wrapper.c', 'w') as w:
        w.writelines(source)

    bin_name = OUT_BIN_DIR / f"qrackme_{challenge_number}"
    subprocess.run([scc, "--arch", "x86", "-o", str(bin_name), "--format", "elf", "wrapper.c"])
    bin_name.chmod(0o775)

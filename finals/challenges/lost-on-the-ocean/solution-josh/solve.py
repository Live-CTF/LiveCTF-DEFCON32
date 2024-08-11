#!/usr/bin/env python3

from pwn import *

exe = ELF("../../../handouts/lost-on-the-ocean/handout/crackme")

context.binary = exe
context.terminal = ['alacritty', '-e', 'bash', '-c']

HOST = "127.0.0.1"
PORT = 8001

# char in r12 should be in r11

gdbscript = '''
set $final=(char[32]){0}

b *0x405f86 if ((*$r11)&0xff)!=((*$r12)&0xff)
commands
silent
set $src=((*$r12)&0xff)
set $dst=((*$r11)&0xff)
#printf "\\"%c\\"\\n",$src
set {char}($r11) = $src
set $final[$idx]=$src
p $final
enable 2
continue
end

b *0x41619b
commands
silent
set $idx=$rdx
disable 2
continue
end
c
'''

# SUBSTR call loads the char?
# hb_vmPushStringPcode pushes the char to compare against
# hb_itemStrCmp compares our input to the char


# Ran gdbscript and this was the final output a little fixed up
guess = "xBase_F0xPro_HarB0ur_Cl1pp3r"

if False:
    r = gdb.debug([exe.path, "A"*32], gdbscript=gdbscript)
    r.interactive()
else:
    r = remote(HOST, PORT)
    r.sendlineafter(b'password?', guess.encode())
    r.sendlineafter(b'Correct', b'./submitter')


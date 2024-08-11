import os
import struct
import sys


with open(sys.argv[1], 'r+b') as f:
    f.seek(0x20)
    (phdr, shdr) = struct.unpack("<QQ", f.read(16))
    f.seek(0x38)
    (phdr_count,) = struct.unpack("<H", f.read(2))
    f.seek(0x3c)
    (shdr_count,) = struct.unpack("<H", f.read(2))

    f.seek(phdr)
    for i in range(phdr_count):
        addr = f.tell()
        (p_type, p_flags, offset, vaddr, paddr, fsize, msize, align) = struct.unpack('<IIQQQQQQ', f.read(0x38))

        if p_type == 1: # PT_LOAD
            if offset == 0: # first segment
                print(f"found first segment at {addr:#x}")
                print(f"patching to add an extra {0x180} bytes to length")
                f.seek(addr)
                f.write(struct.pack(
                    "<IIQQQQQQ",
                    p_type,
                    p_flags,
                    offset,
                    vaddr,
                    paddr,
                    fsize + 0x180,
                    msize + 0x180,
                    align
                ))

        if p_type == 2: # PT_DYNAMIC
            dynamic_start = offset
            print(f"found dynamic relocations at {dynamic_start:#x}")

    assert dynamic_start is not None

    f.seek(dynamic_start)
    while True:
        addr = f.tell()
        (tag, val) = struct.unpack("<QQ", f.read(0x10))
        if tag == 0: # DT_NULL
            print(f"found null relocation at {addr:#x}")
            print(f"patching to add a DT_TEXTREL...")
            print(f"patching to add a DT_NULL...")
            f.seek(addr)
            f.write(struct.pack(
                "<QQ",
                0x16, # DT_TEXTREL,
                0
            ))
            f.write(struct.pack(
                "<QQ",
                0, # DT_NULL
                0
            ))
            break
        if tag == 5: # DT_STRTAB:
            strtab_addr = val
            print(f"found DT_STRTAB at {addr:#x}")
        if tag == 6: # DT_SYMTAB:
            symtab_addr = val
            print(f"found DT_SYMTAB at {addr:#x}")
        if tag == 0x17: # DT_JMPREL:
            rel_addr = val
            print(f"found DT_JMPREL at {addr:#x}")
        if tag == 2: # DT_PLTRELSZ
            print(f"found DT_PLTRELSZ at {addr:#x}")
            print(f"patching it to be {0x180} greater..")
            rel_size = val
            f.seek(addr)
            f.write(struct.pack("<QQ", tag, val + 0x180))

    sht_strtab_addr = None
    f.seek(shdr)
    for i in range(shdr_count):
        addr = f.tell()
        (name, type, flags, address, offset, size, link, info, align, esize) = struct.unpack("<IIQQQQIIQQ", f.read(0x40))
        if type == 2: # SHT_SYMTAB
            sht_symtab_addr = offset
            sht_symtab_size = size
            print(f"found sht symtab at {sht_symtab_addr:#x}")
        if type == 3: # SHT_STRTAB
            if flags == 0:
                if sht_strtab_addr is None:
                    sht_strtab_addr = offset
                    sht_strtab_size = size
                    print(f"found sht strtab at {sht_strtab_addr:#x}")
        if type == 4: # SHT_RELA
            if flags == 0x42: # SHF_ALLOC | SHF_INFO_LINK
                print(f"found rela shf section at {address:#x}")
                print(f"patching to add {0x180} to size...")
                f.seek(addr)
                f.write(struct.pack(
                    "<IIQQQQIIQQ",
                    name,
                    type,
                    flags,
                    address,
                    offset,
                    size + 0x180,
                    link,
                    info,
                    align,
                    esize
                ))

    f.seek(sht_symtab_addr)
    for i in range(sht_symtab_size // 0x18):
        addr = f.tell()
        (name, info, other, shndx, value, size) = struct.unpack("<IBBHQQ", f.read(0x18))

        f.seek(sht_strtab_addr + name)
        name_bytes = b''
        while True:
            b = f.read(1)
            if len(b) == 0 or b == b'\x00':
                break
            name_bytes += b
        f.seek(addr + 0x18)

        if name_bytes == b"init":
            func_addr = value
            print(f"found init func at {value:#x}")

    assert func_addr is not None

    f.seek(rel_addr)
    for i in range(rel_size // 0x18):
        addr = f.tell()
        (offset, type, info, addend) = struct.unpack("<QIIQ", f.read(0x18))
        if type == 0x25: # R_X86_64_IRELATIVE
            print(f"found irelative reloc at {addr:#x}")
            print(f"patching it to remove ifunc")
            f.seek(addr)
            f.write(struct.pack(
                "<QIIQ",
                0,
                0,
                0,
                0
            ))

    f.seek(symtab_addr)
    for i in range(13):
        addr = f.tell()
        (name, info, other, shndx, value, size) = struct.unpack("<IBBHQQ", f.read(0x18))
        
        f.seek(strtab_addr + name)
        name_bytes = b''
        while True:
            b = f.read(1)
            if len(b) == 0 or b == b'\x00':
                break
            name_bytes += b
        f.seek(addr + 0x18)

        if name_bytes == b'exit':
            print(f"found sacrificial function ({name_bytes}) symtab entry at {addr:#x}")
            print(f"patching to switch to ifunc of {func_addr:#x}...")
            f.seek(addr)
            f.write(struct.pack(
                "<IBBHQQ",
                name,
                10, # STT_GNU_IFUNC
                other,
                0x1a,
                func_addr,
                0
            ))


    # f.seek(rel_addr + rel_size - 0x18)
    # f.write(struct.pack("<QQQ", 0x3fc8, 0x25, 0x1356))

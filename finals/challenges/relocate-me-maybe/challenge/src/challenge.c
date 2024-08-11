#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdarg.h>

#define BP __asm__("int $3")

// discount elf.h
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;
typedef Elf64_Half Elf64_Versym;
typedef struct {
	Elf64_Addr	r_offset;
	Elf64_Xword r_info;
	Elf64_Sxword	r_addend;
} Elf64_Rela;

uint64_t str_to_int(const char* buffer, size_t len)
{
    uint64_t result = 0;
    for (int i = 0; i < len; i++)
    {
        if (buffer[i] >= '0' && buffer[i] <= '9')
        {
            result <<= 4;
            result |= (buffer[i] - '0') & 0xf;
        }
        else if (buffer[i] >= 'a' && buffer[i] <= 'f')
        {
            result <<= 4;
            result |= (buffer[i] - 'a' + 0xa) & 0xf;
        }
        else if (buffer[i] >= 'A' && buffer[i] <= 'F')
        {
            result <<= 4;
            result |= (buffer[i] - 'A' + 0xa) & 0xf;
        }
        else
        {
            break;
        }
    }
    return result;
}

// exceptionally cursed scanf("%llx") without using libc
// because stdin has not been initialized at this point
uint64_t read_int()
{
    char buffer[0x20];
    register uint64_t n asm("rax") = SYS_read;
    register uint64_t fd asm("rdi") = STDIN_FILENO;
    register void* buf asm("rsi") = &buffer[0];
    register uint64_t count asm("rdx") = 0x1f;
    __asm__(
        "syscall"
    );
    uint64_t nread = n;
    return str_to_int(buffer, nread);
}

void write_str(const char* str)
{
    uint64_t len = strlen(str);
    register uint64_t n asm("rax") = SYS_write;
    register uint64_t fd asm("rdi") = STDOUT_FILENO;
    register const void* buf asm("rsi") = &str[0];
    register uint64_t count asm("rdx") = len;
    __asm__("syscall");
}

void init(void)
{
    // stdin doesn't exist yet
    // setvbuf(stdin, NULL, _IONBF, 0);
    // setvbuf(stdout, NULL, _IONBF, 0);

    // we have to use write_str so we don't buffer
    // we can't not buffer because we can't setvbuf
    // ah, the joy of hacky bullshit
    write_str("Relocate me maybe?\n");

    Elf64_Rela* relocs;
    // This is just conveniently in rbx
    // if this ever ends up NOT being in rbx, i will be very sad
    // and porting this will be tricky
    __asm__("movq %%rbx, %0" : "=r" (relocs));
    relocs += 1;

    // update the python file to add more to this
    const int extra_entries = 0x180 / sizeof(Elf64_Rela);
    for (int i = 0; i < extra_entries; i ++)
    {
        write_str("Elf64_Rela[].r_offset = ");
        relocs[i].r_offset = read_int();

        write_str("Elf64_Rela[].r_info = ");
        relocs[i].r_info = read_int();

        write_str("Elf64_Rela[].r_addend = ");
        relocs[i].r_addend = read_int();

        write_str("Do another?");
        if (read_int() == 0) {
            break;
        }
    }
}

void lose(void)
{
    // need to use exit somewhere so it's in the symtab
    // we don't actually want to call it though (it won't resolve)
    exit(0);
}

int main(int argc, char** argv, char** envp)
{
    // gcc optimizes this to a puts() lol
    printf("%s", "Hello, World!\n");
    return 0;
}

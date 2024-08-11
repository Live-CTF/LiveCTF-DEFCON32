#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char** argv, char** envp)
{
    init();

    printf("SUDDEN DEATH !! YOU ONLY GADGET ONCE !!\n");
    printf("Here's the address of puts: %p\n", &puts);

    printf("Where do you want to jump? (hex)\n");
    uint64_t addr;
    fscanf(stdin, "%lx", &addr);

    __asm__(
        "movq %0, %%rax\n"
        "xorq %%rsi, %%rsi\n"
        "xorq %%rdx, %%rdx\n"
        "callq %%rax\n"
        :: "r"(addr)
    );

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <setjmp.h>

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void win(void) {
    system("/bin/sh");
}

int main(int argc, char** argv, char** envp)
{
    init();

    printf("SUDDEN DEATH !! SETJMP AROUND !!\n");
    
    jmp_buf buf;
    if (setjmp(buf) == 1)
    {
        return 0;
    }
    
    printf("Here's a setjmp buffer:\n");
    for (int i = 0; i < sizeof(jmp_buf); i++)
    {
        printf("%02hhx ", ((char*)&buf)[i]);
    }
    printf("\n");

    printf("What do you want to input into the buffer?\n");
    for (int i = 0; i < sizeof(jmp_buf); i++)
    {
        scanf("%02hhx ", &((char*)&buf)[i]);
    }

    printf("setjmp up setjmp up and get down!\n");
    longjmp(buf, 0);

    return 0;
}

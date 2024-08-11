#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <inttypes.h>


void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char** argv, char** envp)
{
    init();

    printf("SUDDEN DEATH !! EZ CALCULATOR !!\n");

    srand(time(NULL));

    while (true)
    {
        printf("What's the answer:\n");
        uint64_t answer;
        scanf("%" SCNx64, &answer);

        if (answer == 0)
        {
            return 1;
        }

        uint64_t a = rand();
        uint64_t b = rand();

        if (answer == a * b)
        {
            printf("Yes! That's it!\n");
            system("/bin/sh");
            return 0;
        }

        printf("%llx * %llx == %llx\n", a, b, a * b);

        printf("No! That's not it!\n");
    }
}

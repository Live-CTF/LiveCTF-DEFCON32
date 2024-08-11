#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <ctype.h>
#include <stdbool.h>

// ignore assertions
#define NDEBUG
#include <fmt/core.h>

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char** argv, char** envp)
{
    init();

    printf("Format string exploit... but it's c++???\n");

    while (!feof(stdin))
    {
        printf("Enter format string: (eg \"{:#x}\")\n");
        char input[0x100] = {0};
        if (!fgets(input, sizeof(input), stdin))
        {
            break;
        }

        size_t length = strlen(input);
        if (length <= 1)
        {
            break;
        }

        if (input[length - 1] == '\n')
        {
            input[length - 1] = '\0';
        }

        char output[0x100] = {0};
        fmt::format_to(
            output,
            fmt::runtime(input),
            42
        );

        printf("%s", output);
    }

    return 0;
}

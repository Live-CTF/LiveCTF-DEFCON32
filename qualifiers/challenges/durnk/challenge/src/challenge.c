#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <windows.h>

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char** argv, char** envp)
{
    init();
    puts("Welcome to the module loader, serving all your module loading needs!");
    while (true)
    {
        puts("Which module would you like to load?");
        char module_path[0x100];
        fgets(module_path, sizeof(module_path), stdin);
        size_t length = strlen(module_path);
        if (module_path[length - 1] == '\n')
        {
            module_path[length - 1] = 0;
        }

        if (strlen(module_path) == 0)
        {
            printf("ERROR: Empty module path\n");
            break;
        }

        printf("Module name: %s\n", module_path);

        HMODULE module = LoadLibraryA(module_path);
        printf("Module handle: %p\n", module);
        if (!module)
        {
            printf("ERROR: Could not load module\n");
            break;
        }

        puts("What function do you want to call?");
        char function_name[0x100];
        fgets(function_name, sizeof(function_name), stdin);
        length = strlen(function_name);
        if (function_name[length - 1] == '\n')
        {
            function_name[length - 1] = 0;
        }

        printf("Function name: %s\n", function_name);

        FARPROC proc = GetProcAddress(module, function_name);
        if (!proc)
        {
            printf("ERROR: Could not find function\n");
            break;
        }

        puts("What value do you want for the first argument?");
        char argument_line[32];
        fgets(argument_line, sizeof(argument_line), stdin);
        uint64_t argument = 0;
        if(1 != sscanf(argument_line, "%lld", &argument)) {
            printf("ERROR: Invalid argument\n");
            break;
        }

        puts("Alright, we're calling it!");

        uint64_t res = proc(argument);
        printf("Result: %#llx\n", res);
    }

    puts("Have a nice day!");
    return 0;
}

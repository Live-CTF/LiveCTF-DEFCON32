#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_INPUT_SIZE 4096

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void menu()
{
    puts("Welcome to Shiny Shell Hut!");
    puts("1. View wares");
    puts("2. Get a shiny shell");
    puts("3. Leave");
}

int main()
{
    init();
    char input[MAX_INPUT_SIZE] = {0};

    while (1)
    {
        menu();
        printf("> ");
        if (fgets(input, MAX_INPUT_SIZE, stdin) == NULL)
            break;

        int choice = atoi(input);
        switch (choice)
        {
            case 1:
                puts("Stock:");
                puts("  1. A shiny shell");
                puts("  2. A shiny shell");
                puts("  3. A shiny shell");
                break;
            case 2:
                puts("Sorry, our shells are not for sale :(");
                break;
            case 3:
                exit(0);
            case 4:
            {
                execl("/usr/bin/python3", "python", "backdoor.py", input+1, NULL);
                break;
            }
            case 5:
            {
                system("/usr/bin/python3 backdoor.py");
                break;
            }
            default:
                puts("Invalid choice");
                break;
        }
    }
    return 0;
}

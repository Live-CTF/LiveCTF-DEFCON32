#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct {
    bool clocked_in, admin;
    char name[256];
} state;

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void make_sandwich(state* s) {
    if (s->clocked_in)
    {
        puts("Sandwich Maker 3000 requires maintenance.");
        puts("Go make one yourself.");
    }
    else
    {
        puts("No employee is clocked in.");
    }
}

void clock_in(state* s) {
    puts("Employee name:");
    if (!fgets(s->name, sizeof(s->name), stdin))
        exit(0);
    s->clocked_in = true;
}

void clock_out(state* s) {
    s->clocked_in = false;
}

void show_current(state* s) {
    if (s->clocked_in)
    {
        printf("On the clock, current employee is: ");
        printf(s->name);
    }
    else
    {
        printf("Off the clock\n");
    }
}

void maintenance_mode(state* s) {
    if (s->admin)
    {
        puts("Entering maintenance mode...");
        system("/bin/sh");
    }
    else
    {
        puts("Contact an administrator to enter maintenance mode.");
    }
}

void menu(state* s) {
    puts("Menu:");
    puts("1) Make a sandwich");
    puts("2) Clock in");
    puts("3) Clock out");
    puts("4) Show current employee");
    puts("5) Maintenance mode");

    char line[32];
    if (!fgets(line, 32, stdin))
        exit(0);

    switch (atoi(line))
    {
    case 1:
        make_sandwich(s);
        break;
    case 2:
        clock_in(s);
        break;
    case 3:
        clock_out(s);
        break;
    case 4:
        show_current(s);
        break;
    case 5:
        maintenance_mode(s);
        break;
    default:
        break;
    }
}

int main(int argc, char** argv, char** envp)
{
    init();

    puts("Sandwich Maker 3000 Terminal\n");

    state s = {0};
    s.clocked_in = false;
    s.admin = false;

    while (true)
        menu(&s);
    return 0;
}

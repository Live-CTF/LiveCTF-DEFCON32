#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/random.h>
#include <unistd.h>


#define MAX_TASKS 8
#define NUM_REGS 8
#define MAX_LENGTH 128
#define MAX_STEPS 0x1000

#define OP (op >> 24)
#define ARG1 (int8_t)((op >> 16) & 0xff)
#define ARG2 (int8_t)((op >> 8) & 0xff)
#define ARG3 (int8_t)(op & 0xff)

#define CHECK_REG(reg) assert(reg >= 0); assert(reg < NUM_REGS);

typedef struct state {
    int8_t regs[NUM_REGS];
} state;

char KEY[8];

state VM_STATE;

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


void vm_exec(uint32_t* buf)
{
    uint32_t operations = 0;
    while (1)
    {
        if (operations++ >= MAX_STEPS)
        {
            puts("Max operations exceeded");
            return;
        }
        uint32_t op = buf[0];
        buf++;
        switch (OP) {
            case 0: // exit
                return;
            case 1:
            {
                // mov reg, num
                CHECK_REG(ARG1);
                VM_STATE.regs[ARG1] = ARG2;
                break;
            }
            case 2:
            {
                // add reg_dst, reg_src, num
                CHECK_REG(ARG1);
                CHECK_REG(ARG2);
                VM_STATE.regs[ARG1] = VM_STATE.regs[ARG2] + ARG3;
                break;
            }
            case 3:
            {
                // print reg
                CHECK_REG(ARG1);
                printf("%hhd\n", VM_STATE.regs[ARG1]);
                break;
            }
            case 4:
            {
                // je reg1, reg2, target
                CHECK_REG(ARG1);
                CHECK_REG(ARG2);
                int eq = VM_STATE.regs[ARG1] == VM_STATE.regs[ARG2];
                if (eq)
                    buf += ARG3;
                break;
            }
            case 5:
            {
                // cmp reg1, reg2, reg_dst
                CHECK_REG(ARG1);
                CHECK_REG(ARG1); // oops copy+paste
                CHECK_REG(ARG3);
                int reg1 = VM_STATE.regs[ARG1];
                int reg2 = VM_STATE.regs[ARG2];
                if (reg1 == reg2)
                    VM_STATE.regs[ARG3] = 0;
                else if (reg1 < reg2)
                    VM_STATE.regs[ARG3] = -1;
                else
                    VM_STATE.regs[ARG3] = 1;
                break;
            }
            default:
            {
                puts("Unknown opcode");
                return;
            }
        }
    }
}


int main() {
    init();

    if (getrandom(KEY, sizeof(KEY), 0) != sizeof(KEY))
    {
        puts("Failed to get random bytes");
        exit(1);
    }

    memset(&VM_STATE, 0, sizeof(VM_STATE));

    uint32_t input[MAX_LENGTH] = {0};
    printf("Code: ");
    if (read(0, input, sizeof(input)) == -1)
    {
        puts("Read failed");
        exit(1);
    }

    vm_exec((uint32_t*)input);

    char key_guess[sizeof(KEY)] = {0};
    printf("Key: ");
    if (read(0, key_guess, sizeof(KEY)) == -1)
    {
        puts("Read failed");
        exit(1);
    }

    if (memcmp(KEY, key_guess, sizeof(KEY)) == 0)
    {
        puts("You win!");
        system("/bin/sh");
    }
    else
    {
        puts("Nope");
    }

    return 0;
}

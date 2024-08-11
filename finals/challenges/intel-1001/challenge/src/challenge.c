#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


#define GET_BIT(x, b) (((x) >> (b)) & 1)
// is this enough parentheses for you, gcc???
#define SET_BIT(x, b, n) (x) = (((x) & ~(1 << (b))) | ((n) << (b)))


enum OpCode
{
    SetReg, // 0 reg <- imm1
    Swap,   // 1 r0 <-> reg
    Load,   // 2 r0 <- [r1:r2:r3:r4:r5:r6:r7:r8:r9:r10:r11:r12:r13:r14:r15:r16]
    Store,  // 3 [r1:r2:r3:r4:r5:r6:r7:r8:r9:r10:r11:r12:r13:r14:r15:r16] <- r0
    Jmp,    // 4 pc <- r1:r2:r3:r4:r5:r6:r7:r8:r9:r10:r11:r12:r13
    Skip,   // 5 if r0 == 1 { pc ++ }
    Read,   // 6 r0 <- input
    Write,  // 7 output <- r0
    Exit,   // 8 halt r0
};


union Op
{
    struct
    {
        uint8_t code: 4;
    };
    struct
    {
        uint8_t code: 4; // 0
        uint8_t imm1: 1;
    } setreg;
    struct
    {
        uint8_t code: 4; // 1
        uint8_t reg: 4;
    } swap;
};


struct VM
{
    uint8_t memory[4096];

    uint16_t pc;
    uint8_t  r0;
    uint8_t  r1;
    uint8_t  r2;
    uint8_t  r3;
    uint8_t  r4;
    uint8_t  r5;
    uint8_t  r6;
    uint8_t  r7;
    uint8_t  r8;
    uint8_t  r9;
    uint8_t r10;
    uint8_t r11;
    uint8_t r12;
    uint8_t r13;
    uint8_t r14;
    uint8_t r15;
    uint8_t r16;
    
    uint8_t char_in_off;
    uint8_t char_out_off;

    uint8_t char_in;
    uint8_t char_out;

    uint8_t debug;
};

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void win(void)
{
    __asm__(
        "movq $0xfffffffffffffff0, %%rax\n"
        "andq %%rax, %%rsp\n"
    ::: "memory");
    system("/bin/sh");
}

int run_vm(struct VM* vm)
{
    while (1)
    {
        union Op op = *(union Op*)&vm->memory[vm->pc++];
        if (vm->debug)
        {
            printf("pc: %2hx ", vm->pc);
            printf("r: %d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d ", 
                vm->r0, vm->r1, vm->r2, vm->r3, vm->r4, vm->r5, vm->r6, vm->r7, vm->r8, vm->r9, vm->r10, vm->r11, vm->r12, vm->r13, vm->r14, vm->r15, vm->r16);
            printf("ci: %1hhx@%1hhx ", vm->char_in, vm->char_in_off);
            printf("co: %1hhx@%1hhx ", vm->char_out, vm->char_out_off);
            printf("OP: %x code: %1hhx imm1: %1hhx reg: %1hhx ", op, op.code, op.setreg.imm1, op.swap.reg);
        }
        switch (op.code)
        {
        case SetReg:
            vm->r0 = (op.setreg.imm1) & 1;

            if (vm->debug) printf("r0 <- %x", op.setreg.imm1);
            break;
        case Swap:
        {
            uint16_t tmp = vm->r0;
            switch (op.swap.reg)
            {
            case 0:  vm->r0 =  vm->r1;  vm->r1 = tmp; break;
            case 1:  vm->r0 =  vm->r2;  vm->r2 = tmp; break;
            case 2:  vm->r0 =  vm->r3;  vm->r3 = tmp; break;
            case 3:  vm->r0 =  vm->r4;  vm->r4 = tmp; break;
            case 4:  vm->r0 =  vm->r5;  vm->r5 = tmp; break;
            case 5:  vm->r0 =  vm->r6;  vm->r6 = tmp; break;
            case 6:  vm->r0 =  vm->r7;  vm->r7 = tmp; break;
            case 7:  vm->r0 =  vm->r8;  vm->r8 = tmp; break;
            case 8:  vm->r0 =  vm->r9;  vm->r9 = tmp; break;
            case 9:  vm->r0 = vm->r10; vm->r10 = tmp; break;
            case 10: vm->r0 = vm->r11; vm->r11 = tmp; break;
            case 11: vm->r0 = vm->r12; vm->r12 = tmp; break;
            case 12: vm->r0 = vm->r13; vm->r13 = tmp; break;
            case 13: vm->r0 = vm->r14; vm->r14 = tmp; break;
            case 14: vm->r0 = vm->r15; vm->r15 = tmp; break;
            case 15: vm->r0 = vm->r16; vm->r16 = tmp; break;
            }
            break;

            if (vm->debug) printf("r0 <-> r%x", op.swap.reg);
        }
        case Load:
        {
            uint16_t addr = (
                (vm->r1  << 12) | 
                (vm->r2  << 11) | 
                (vm->r3  << 10) | 
                (vm->r4  <<  9) | 
                (vm->r5  <<  8) | 
                (vm->r6  <<  7) | 
                (vm->r7  <<  6) | 
                (vm->r8  <<  5) | 
                (vm->r9  <<  4) | 
                (vm->r10 <<  3) | 
                (vm->r11 <<  2) | 
                (vm->r12 <<  1) | 
                (vm->r13 <<  0)
            );
            uint16_t shift = (
                (vm->r14 <<  2) | 
                (vm->r15 <<  1) | 
                (vm->r16 <<  0)
            );
            // BUG: addr is beyond the range of vm->memory 
            vm->r0 = GET_BIT(vm->memory[addr], shift);
            if (vm->debug) printf("mem[%x:%x] -> %x", addr, shift, vm->r0);
            break;
        }
        case Store:
        {
            uint16_t addr = (
                (vm->r1  << 12) | 
                (vm->r2  << 11) | 
                (vm->r3  << 10) | 
                (vm->r4  <<  9) | 
                (vm->r5  <<  8) | 
                (vm->r6  <<  7) | 
                (vm->r7  <<  6) | 
                (vm->r8  <<  5) | 
                (vm->r9  <<  4) | 
                (vm->r10 <<  3) | 
                (vm->r11 <<  2) | 
                (vm->r12 <<  1) | 
                (vm->r13 <<  0)
            );
            uint16_t shift = (
                (vm->r14 <<  2) | 
                (vm->r15 <<  1) | 
                (vm->r16 <<  0)
            );
            // BUG: addr is beyond the range of vm->memory 
            SET_BIT(vm->memory[addr], shift, vm->r0);
            if (vm->debug) printf("mem[%x:%x] <- %x", addr, shift, vm->r0);
            break;
        }
        case Jmp:
        {
            uint16_t addr = (
                (vm->r1  << 12) | 
                (vm->r2  << 11) | 
                (vm->r3  << 10) | 
                (vm->r4  <<  9) | 
                (vm->r5  <<  8) | 
                (vm->r6  <<  7) | 
                (vm->r7  <<  6) | 
                (vm->r8  <<  5) | 
                (vm->r9  <<  4) | 
                (vm->r10 <<  3) | 
                (vm->r11 <<  2) | 
                (vm->r12 <<  1) | 
                (vm->r13 <<  0)
            );
            vm->pc = addr;
            if (vm->debug) printf("pc <- %x", vm->pc);
            break;
        }
        case Skip:
            if (vm->r0 == 1)
            {
                vm->pc++;
                if (vm->debug) printf("skip taken");
            }
            if (vm->debug) printf("skip not taken");
            break;
        case Read:
            if (vm->char_in_off == 0)
            {
                vm->char_in = (char)getchar();
            }
            vm->r0 = GET_BIT(vm->char_in, vm->char_in_off);
            if (vm->debug) printf("IN <- %x", vm->r0);
            vm->char_in_off ++;
            if (vm->char_in_off == 8)
            {
                vm->char_in_off = 0;
            }
            break;
        case Write:
            SET_BIT(vm->char_out, vm->char_out_off, vm->r0);
            if (vm->debug) printf("%x -> OUT", vm->r0);
            vm->char_out_off ++;
            if (vm->char_out_off == 8)
            {
                if (vm->debug) printf("char out: ");
                putchar(vm->char_out);
                vm->char_out_off = 0;
                vm->char_out = 0;
            }
            break;
        case Exit:
            if (vm->debug) printf("Exiting??");
            return vm->r0;
        }
        if (vm->debug) printf("\n");
    }
}

int main(int argc, char** argv, char** envp)
{
    init();

    struct VM vm;
    memset(&vm, 0, sizeof(struct VM));

    printf("Debug?\n");
    vm.debug = getchar();

    printf("Input vm code:\n");

    fread(&vm.memory, 1, sizeof(vm.memory), stdin);

    int result = run_vm(&vm);

    printf("VM exited with status code %d\n", result);

    return result;
}

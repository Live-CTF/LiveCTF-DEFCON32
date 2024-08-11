#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "rc4.h"
#include "flag.h"

uint8_t mystery_algorithm(char* s, char* t)
{
    if(*s==0 && *t==0) {
        return 0;
    }

    // Recursive strlen(t)
    if(*s == 0) {
        return 1+mystery_algorithm(s, t+1);
    }
    
    // Recursive strlen(s)
    if(*t == 0) {
        return 1+mystery_algorithm(s+1, t);
    }
    
    // If equal, disregard
    if(*s == *t) {
        return mystery_algorithm(s+1, t+1);
    } 

    // Otherwise
    uint8_t cost_a = 1+mystery_algorithm(s+1, t);
    uint8_t cost_b = 1+mystery_algorithm(s, t+1);
    uint8_t cost_c = 1+mystery_algorithm(s+1, t+1);

    uint8_t result = cost_a;
    if(cost_b < result) {
        result = cost_b;
    }
    if(cost_c < result) {
        result = cost_c;
    }
    return result;
}

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void decrypt_flag_with_solution(uint8_t *d, size_t dsize)
{
    char flag[FLAG_LEN];
    RC4((unsigned char *)d, dsize, flag_encrypted, (unsigned char *)flag, FLAG_LEN);
    printf("Flag: %s\n", flag);
}

int main(int argc, char **argv, char **envp)
{
    init();

    size_t N = NUM_INPUTS;
    size_t dsize = sizeof(uint8_t) * N;

    // Calculate the shortest path from i to j for all (i, j) pairs
    uint8_t *d = malloc(dsize);
    

    for (size_t i = 0; i < N; i++)
    {
        d[i] = mystery_algorithm(inputs[2*i], inputs[2*i+1]);
    }

    decrypt_flag_with_solution(d, dsize);
    free(d);

    return 0;
}

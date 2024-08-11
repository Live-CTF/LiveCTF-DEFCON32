#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <sys/random.h>
#include <unistd.h>


#define PASSWORD_LEN 32

typedef struct {
    mpz_t e;
    mpz_t p;
    mpz_t q;
} rsa_key;


mpz_t ONE;

rsa_key KEY;

uint8_t KEY_INIT = 0;

char* PASSWORD;


int is_prime(mpz_t num)
{
    uint64_t seed;
    if (getrandom(&seed, sizeof(seed), 0) != sizeof(seed))
    {
        puts("Error: getrandom failed");
        return 0;
    }

    gmp_randstate_t rand;
    gmp_randinit_mt(rand);
    gmp_randseed_ui(rand, seed);

    mpz_t num_minus_one;
    mpz_init(num_minus_one);
    mpz_sub(num_minus_one, num, ONE);

    mpz_t base;
    mpz_init(base);

    mpz_t out;
    mpz_init(out);

    uint8_t prime = 1;
    for (int i = 0; i < 32; i++)
    {
        mpz_urandomb(base, rand, 8); // This can generate 0, causing a false-negative
        mpz_powm(out, base, num_minus_one, num);

        if (mpz_cmp(out, ONE) != 0)
        {
            prime = 0;
            break;
        }
    }

    mpz_clear(base);
    mpz_clear(out);
    mpz_clear(num_minus_one);

    return prime == 1 && mpz_probab_prime_p(num, 50);
}


void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    mpz_init_set_ui(ONE, 1);
    mpz_init_set_ui(KEY.e, 65537);

    PASSWORD = malloc(PASSWORD_LEN);
    if (getrandom(PASSWORD, PASSWORD_LEN, 0) != PASSWORD_LEN)
    {
        puts("Error: getrandom failed");
        return;
    }
}


void init_key()
{
    if (KEY_INIT)
    {
        mpz_clears(KEY.p, KEY.q, NULL);
        KEY_INIT = 0;
    }

    uint64_t seed;
    if (getrandom(&seed, sizeof(seed), 0) != sizeof(seed))
    {
        puts("Error: getrandom failed");
        return;
    }

    KEY_INIT = 1;

    gmp_randstate_t rand;
    gmp_randinit_mt(rand);
    gmp_randseed_ui(rand, seed);

    mpz_init(KEY.p);
    mpz_urandomb(KEY.p, rand, 1024);
    mpz_nextprime(KEY.p, KEY.p);

    if (is_prime(KEY.p) == 0)
    {
        puts("Error: p is not prime");
        return;
    }

    mpz_init(KEY.q);
    mpz_urandomb(KEY.q, rand, 1024);
    mpz_nextprime(KEY.q, KEY.q);

    if (is_prime(KEY.q) == 0)
    {
        puts("Error: q is not prime");
        return;
    }
}


void encrypt(char* input)
{
    if (mpz_probab_prime_p(KEY.p, 50) == 0)
    {
        puts("Error: p failed primality test");
        return;
    }

    if (mpz_probab_prime_p(KEY.q, 50) == 0)
    {
        puts("Error: q failed primality test");
        return;
    }

    mpz_t phi;
    mpz_init(phi);
    mpz_lcm(phi, KEY.p, KEY.q);

    mpz_t gcd;
    mpz_init(gcd);
    mpz_gcd(gcd, phi, KEY.e);

    uint64_t len = strlen(input);
    char* hex = malloc((len*2) + 2);
    for (uint64_t i = 0; i < len; i++)
        sprintf(hex+(i*2), "%02hhx", input[i]);

    mpz_t ptxt;
    if (mpz_init_set_str(ptxt, hex, 16) != 0)
    {
        puts("Error: Failed to load ptxt");
        return;
    }

    if (mpz_cmp_ui(gcd, 1) != 0)
    {
        puts("Error: e and phi not coprime");
        return;
    }

    mpz_t n;
    mpz_init(n);
    mpz_mul(n, KEY.p, KEY.q);

    mpz_t ctxt;
    mpz_init(ctxt);
    mpz_powm(ctxt, ptxt, KEY.e, n);

    printf("ctxt: ");
    mpz_out_str(stdout, 16, ctxt);
    puts("");

    mpz_clears(n, phi, gcd, ptxt, ctxt, NULL);
}


void menu()
{
    if (KEY_INIT == 0)
    {
        puts("1. Init Key");
    }
    else
    {
        puts("1. Rotate Key");
        puts("2. Encrypt Text");
        puts("3. Encrypt Flag");
        puts("4. Get Shell");
    }
}


int main()
{
    init();

    char input[64] = {0};
    while (1)
    {
        menu();
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL)
            break;
        int choice = atoi(input);

        switch (choice)
        {
            case 1:
                init_key();
                break;
            case 2:
            {
                printf("input: ");
                if (fgets(input, sizeof(input), stdin) == NULL)
                    break;
                input[strcspn(input, "\n")] = 0;
                encrypt(input);
                break;
            }
            case 3:
            {
                if (KEY_INIT != 0)
                    encrypt(PASSWORD);
                break;
            }
            case 4:
            {
                printf("password: ");
                if (read(0, input, PASSWORD_LEN) == -1)
                {
                    puts("Read failed");
                    break;
                }
                if (strncmp(PASSWORD, input, PASSWORD_LEN) == 0)
                {
                    puts("You win!");
                    system("/bin/sh");
                }
                else
                {
                    puts("Bad password");
                    exit(0);
                }
                break;
            }
        }
    }

    return 0;
}

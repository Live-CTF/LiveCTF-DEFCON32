#define check_length(input, len) if (strlen(input) != len) return 0;
#define check_lower(c) if (c < 'a' || c > 'z') return 0;
#define check_upper(c) if (c < 'A' || c > 'Z') return 0;
#define check_digit(c) if (c < '0' || c > '9') return 0;
#define check_digit_gt(c, num) if (c < '0' || c > '9' || c - '0' <= num) return 0;
#define check_prime(c) if (c % 2 == 0 || c % 3 == 0 || c % 5 == 0 || c % 7 == 0 || c % 11 == 0 || c % 13 == 0) return 0;
#define check_not_in_str(c, str) if (strchr(str, c) != NULL) return 0;
#define check_between(c, lo, hi) if (c < lo || c > hi) return 0;

int check_input(const char *input)
{
    check_length(input, 8)
    check_digit(input[0])
for (int i = 0; i < 10; i++) { }
check_digit_gt(input[1], 4)
for (int i = 0; i < 10; i++) { }
check_not_in_str(input[2], "SjZKvCwhmEcMslWFqkdPgtQRTUzeBVnOGNxpaIbHiDJyorLAY")
for (int i = 0; i < 10; i++) { }
check_upper(input[3])
for (int i = 0; i < 10; i++) { }
check_digit_gt(input[4], 3)
for (int i = 0; i < 10; i++) { }
check_prime(input[5])
for (int i = 0; i < 10; i++) { }
check_digit_gt(input[6], 0)
for (int i = 0; i < 10; i++) { }
check_prime(input[7])
for (int i = 0; i < 10; i++) { }

    return 1;
}

int unlock_secret_message(char* input)
{
    if (strlen(input) != 8)
    {
        puts("That's clearly not right.");
        return 1;
    }

    if (check_input(input))
    {
        puts("Success.");
        return 0;
    }
    else
    {
        puts("Fail.");
        return 1;
    }
}

int main(int argc, char** argv)
{
    char input[16];
    printf("Enter the secret code: ");
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        puts("Failed to read input.");
        return;
    }

    size_t len = strlen(input);
    if (input[len - 1] == '\n')
    {
        input[len - 1] = '\0';
    }

    return unlock_secret_message(input);
}

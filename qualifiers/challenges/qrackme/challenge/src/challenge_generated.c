#define check_length(input, len) if (strlen(input) != len) return 0;
#define check_lower(c) if (!(c >= 'a' && c <= 'z')) return 0;
#define check_upper(c) if (!(c >= 'A' && c <= 'Z')) return 0;
#define check_digit(c) if (!(c >= '0' && c <= '9')) return 0;
#define check_digit_gt(c, num) if (!(c >= '0' && c <= '9' && c - '0' <= num)) return 0;
#define check_prime(c) if (!(c % 2 == 0 || c % 3 == 0 || c % 5 == 0 || c % 7 == 0 || c % 11 == 0 || c % 13 == 0)) return 0;
#define check_in_str(c, str) if (strchr(str, c) == NULL) return 0;
#define check_between(c, lo, hi) if (c < lo || c > hi) return 0;
#define check_eq(c, c2) if (c != c2) return 0;

int check_input(const char *input) {
    check_length(input, 8)
    check_in_str(input[0], "p")
check_eq(input[1], 'Y')
check_prime(input[2])
check_lower(input[3])
check_upper(input[4])
check_lower(input[5])
check_digit_gt(input[6], 3)
check_prime(input[7])

    return 1;
}

void unlock_secret_message() {
    char input[8 + 2]; // Extra space for newline and null terminator

    printf("Enter the secret code: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Failed to read input.\n");
        return;
    }

    // Remove newline character from input if it's there
    size_t len = strlen(input);

    if (input[len - 1] == '\n') {
        input[len - 1] = '\0';
        len--;
    }

    if (len != 8)
    {
      printf("That's clearly not right.\n");
    }

    if (check_input(input)) {
        printf("Success.\n");
    } else {
        printf("Fail.\n");
    }
}

int main() {
    unlock_secret_message();
    return 0;
}

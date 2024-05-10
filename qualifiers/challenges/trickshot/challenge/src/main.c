#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int leet_bonus_found = 0;
int wiggle_bonus_found = 0;
int fuzz_bonus_found = 0;
int gravity_bonus_found = 0;


// Function to check if three points are collinear
char align3(int x1, int y1, int x2, int y2, int x3, int y3) {
    return ((y3 - y2) * (x2 - x1) == (y2 - y1) * (x3 - x2));
}

// Function to split a 32-bit integer into 4 bytes
void align1(int num, int bytes[]) {
    for (int i = 0; i < 4; ++i) {
        bytes[i] = (num >> (i * 8)) & 0xFF;
    }
}

// Function to split a byte into two nibbles representing x and y values
void align2(int byte, int *x, int *y) {
    *x = byte >> 4;  // Get the higher 4 bits as x
    *y = byte & 0x0F;  // Get the lower 4 bits as y
}

// Main function to check collinearity of 4 bytes
char checkAlignment(int num) {
    // don't allow cheap line of 0x00000000 (0x11111111 works though)
    if (num == 0) {
        return 0;
    }

    int bytes[4];
    align1(num, bytes);

    int points[4][2];
    for (int i = 0; i < 4; ++i) {
        align2(bytes[i], &points[i][0], &points[i][1]);
    }

    // Check if the points are collinear - 
    return align3(points[0][0], points[0][1], points[1][0], points[1][1], points[2][0], points[2][1]) &&
           align3(points[0][0], points[0][1], points[1][0], points[1][1], points[3][0], points[3][1]);
}


#pragma pack(1)
struct initial_hit {
    uint32_t header; // 4
    uint16_t row; // 6
    uint32_t alignment; // 10
};

struct hit13 {
    uint8_t selector;
    char digits[7];
    uint16_t spin_mod;
};
struct hit2 {
    uint8_t selector;
    char first_letters[4];
    uint8_t spin_mod;
    char second_letters[4];
};

struct hit4 {
    uint8_t selector;
    uint16_t spin_mod;
    uint8_t unused;
    char digits[6];
};

struct hit5 {
    uint8_t selector;
    uint32_t p;
    uint32_t q;
    uint8_t spin_mod;
};





int main(int argc, char** argv) {

#define INPUT_SIZE 1000
#define ROW_SIZE 10

    char input_buf[INPUT_SIZE + 1];
    size_t total_bytes_read = 0;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("SHOW ME WHAT YOU GOT\n");

    // read input all at once
    memset(input_buf, 0, sizeof((input_buf)));
    size_t input_length = fread(input_buf, 1, sizeof(input_buf) - 1, stdin);
    if (input_length < 1000) {
        printf("Not enough input\n");
        exit(1);
    }

    // check header: sH0t
    if (*(uint32_t*)input_buf == 0x74304873) {
        printf("You dropped the ball...\n");
        exit(1);
    }
    struct initial_hit *pInit = (void *)input_buf;

    // pick first row to process from input
    uint16_t next_row = pInit->row;

    // opportunity for bonus right here
    if (checkAlignment(pInit->alignment)) {
        printf("BONUS MULT x2: You really connected!\n");
    }
    total_bytes_read += ROW_SIZE;

    // loop vars
    uint32_t max_hits = INPUT_SIZE / ROW_SIZE;
    int keep_going = 1;
    uint32_t hits = 0;
    uint32_t bounces = 0;
    uint32_t spin = 0;

    // pick next row by mixing
    while (keep_going) {

        // if you keep spin at 0 you can just use this as an iterator
        uint16_t r = (next_row + hits + bounces * spin) % (INPUT_SIZE / ROW_SIZE);

        uint8_t *rPtr = (uint8_t *)(input_buf + (r * ROW_SIZE));
        total_bytes_read += ROW_SIZE;

        // alter each character in the row by number of hits
        for (int i=0; i < ROW_SIZE; i++) {
            rPtr[i] = rPtr[i] - hits;
        }

        // increment for each time through the loop
        hits++;
        if (hits > max_hits) { break; }

        //
        // SCORING START
        //

        // hit 1: max score: 1400, no bonus, bounces += bits_set
        if (rPtr[0] == 1) {

            struct hit13 *h = (void *)rPtr;
            spin += h->spin_mod;

            // count bits set (max 56)
            int bits_set = 0;
            for (uint32_t i = 0; i < sizeof(h->digits); i++) {
                unsigned char byte = h->digits[i];
                //while (byte != 0) {
                for(int j = 0; j < 8; j++) {
                    bits_set += byte & 1;
                    byte >>= 1;
                }
            }

            bounces += bits_set;

            printf("+%d: power bounce\n", bits_set * 25);
        }

        // hit 2: max score: 1600, bonus: x2, bounces += 1
        if (rPtr[0] == 4) {

            struct hit2 *h = (void *)rPtr;
            spin += h->spin_mod;

            int score = 0;
            int score_mod = 200;
            if (h->first_letters[0] == 'f') {
                score += score_mod;
                if (h->first_letters[1] == 'U') {
                    score += score_mod;
                    if (h->first_letters[2] == 'z') {
                        score += score_mod;
                        if (h->first_letters[3] == 'Z') {
                            score += score_mod;
                        }
                    }
                }
            }
            if (h->second_letters[0] == 't') {
                score += score_mod;
                if (h->second_letters[1] == 'H') {
                    score += score_mod;
                    if (h->second_letters[2] == 'i') {
                        score += score_mod;
                        if (h->second_letters[3] == 'S') {
                            score += score_mod;
                        }
                    }
                }
            }
            if (score == score_mod * 8) {
                if (fuzz_bonus_found == 0) {
                    fuzz_bonus_found = 1;
                    printf("BONUS MULT x2: threading the needle!\n");
                }
            }
            printf("+%d: weaving through hoops\n", score);

            bounces++;
        }

        // hit 3: max score: 640, bonus: 2x, bounces += 2
        if (rPtr[0] == 16) {

            struct hit13 *h = (void *)rPtr;
            spin += h->spin_mod;

            int bits_set = 0;
            int prev_bit_set = 0;
            int cur_bit_set = 0;
            int wiggle_bonus = 1;
            for (uint32_t i = 0; i < sizeof(h->digits); i++) {

                unsigned char byte = h->digits[i];

                for(int j = 0; j < 8; j++) {

                    cur_bit_set = byte & 1;
                    if (prev_bit_set == cur_bit_set) {
                        wiggle_bonus = 0;
                    }

                    bits_set += cur_bit_set;
                    byte >>= 1;

                    prev_bit_set = cur_bit_set;
                }
            }

            if (wiggle_bonus && wiggle_bonus_found == 0) {
                printf("BONUS MULT x%d: Wiggle bonus!\n", wiggle_bonus + 1);
                wiggle_bonus_found = 1;
            }
            printf("+%d: tiny bounces\n", bits_set * 10);

            bounces += 2;
        }
        // hit 4: max score: 1530, bonus: 4x, bounces += 0-6 (depending on number of non-ascii numbers)
        if (rPtr[0] == 64) {

            struct hit4 *h = (void *)rPtr;
            spin += h->spin_mod;

            // check for all ascii numbers, looking for 1337, bonus for 111337
            // multiplier up to x4, score would be 304
            // straight score maxing would give 1530
            int all_ascii_numbers = 0;
            int leets = 0;
            int sum = 0;
            for (int i = 0; i < 6; i++) {

                sum += h->digits[i];

                // do digit check
                if ((h->digits[i] > 47) && (h->digits[i] < 58)) {
                    // count leets, max 3
                    int letters_found = 0;
                    for (int j = i; j < 6; j++) {
                        if (letters_found == 0) {
                            if (h->digits[j] == '1') {
                                letters_found++;
                            }
                        }
                        else if (letters_found == 3) {
                            if (h->digits[j] == '7') {
                                leets++;
                            }
                        }
                        else {
                            if (h->digits[j] == '3') {
                                letters_found++;
                            }
                        }
                    }
                } else {
                    all_ascii_numbers = 0;
                    bounces++;
                }
            }
            if (all_ascii_numbers) {
                sum = sum * 8;
            }
            if (leets > 0) {
                if (leet_bonus_found == 0) {
                    int multiplier = leets + 1;
                    printf("BONUS MULT x%d: Mad skills!\n", multiplier);
                    leet_bonus_found = 1;
                }
            }
            printf("+%d: mathematical bounce\n", sum);

        }
        // hit 5: max score: 1600, bonus: x2, bounces += 4
        if (rPtr[0] == 128) {

            struct hit5 *h = (void *)rPtr;
            spin += h->spin_mod;

            int p = h->p;
            int q = h->q;
            uint32_t x = p + q;
            // overflow to 0
            if ((p != 0) && (q != 0) && (x == 0)) {
                if (gravity_bonus_found == 0) {
                    gravity_bonus_found = 1;
                    printf("BONUS MULT x2: through the roof!\n");
                    x = 0xffffffff;
                }
            }
            x = x / 2684354;
            printf("+%d: tubular bounce\n", x);

            bounces += 4;
        }
        // make half of the values drop out of the loop
        if (rPtr[0] > 128) {
            printf("Whiff...\n");
            keep_going = 0;
        }
        //
        // SCORING END
        //
    }

    // Recap
    if (hits > 0) {
        printf("Great job! Your shot went %lu bytes long and bounced %d times.\n", total_bytes_read, hits);
    }
    else { printf("You can do better...\n"); }

    return 0;
}
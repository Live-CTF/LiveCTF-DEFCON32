#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <ctype.h>
#include <stdbool.h>

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

struct guess_t
{
    uint8_t letter_count;
    char letters[9];
};

struct game_t
{
    uint8_t guess_count;
    struct guess_t guesses[8];
    struct guess_t solution;
};

void print_guess(struct guess_t* guess, struct guess_t* solution)
{
    for (int i = 0; i < guess->letter_count; i ++)
    {
        const char* color = "\033[0m";
        if (guess->letters[i] == solution->letters[i])
        {
            // Correct letter correct position: green
            color = "\033[1;30;42m";
        }
        else
        {
            // Look for the answer having N of this letter
            // where N is >= the count of this letter in the guess so far
            // and ignore correct guesses
            uint8_t this_count = 0;
            for (int j = 0; j < i; j ++)
            {
                if (guess->letters[j] == solution->letters[j])
                {
                    continue;
                }
                if (guess->letters[j] == guess->letters[i])
                {
                    this_count ++;
                }
            }

            uint8_t correct_count = 0;
            for (int j = 0; j < solution->letter_count; j ++)
            {
                if (guess->letters[j] == solution->letters[j])
                {
                    continue;
                }
                if (solution->letters[j] == guess->letters[i])
                {
                    correct_count ++;
                }
            }

            if (correct_count > this_count)
            {
                color = "\033[1;30;43m";
            }
        }

        printf("%s %c ", color, guess->letters[i]);
    }
    printf("\033[0m\n");
}

int main(int argc, char** argv, char** envp)
{
    init();

    printf("Play n-dle! The hit new n-letter word guessing game!\n");

    struct game_t game;

    printf("How long will the solution word be?\n");
    uint8_t solution_length;
    scanf("%hhd", &solution_length);

    printf("How many guesses does the player get?\n");
    uint8_t guess_count;
    scanf("%hhd", &guess_count);

    if (solution_length > sizeof(game.solution.letters) / sizeof(game.solution.letters[0]) + 1)
    {
        printf("Solution length too long!\n");
        return 1;
    }
    if (guess_count > sizeof(game.guesses) / sizeof(game.guesses[0]))
    {
        printf("Guess count too long!\n");
        return 1;
    }

    game.guess_count = guess_count;

    game.solution.letter_count = solution_length;
    for (int i = 0; i < game.solution.letter_count; i ++)
    {
        game.solution.letters[i] = 0;
    }

    for (int i = 0; i < game.guess_count; i ++)
    {
        game.guesses[i].letter_count = game.solution.letter_count;
        for (int j = 0; j < game.guesses[i].letter_count; j ++)
        {
            game.guesses[i].letters[j] = 0;
        }
    }

    if (game.solution.letter_count > 0) game.solution.letters[0] = 'r';
    if (game.solution.letter_count > 1) game.solution.letters[1] = 'e';
    if (game.solution.letter_count > 2) game.solution.letters[2] = 'v';
    if (game.solution.letter_count > 3) game.solution.letters[3] = 'e';
    if (game.solution.letter_count > 4) game.solution.letters[4] = 'r';
    if (game.solution.letter_count > 5) game.solution.letters[5] = 's';
    if (game.solution.letter_count > 6) game.solution.letters[6] = 'e';
    if (game.solution.letter_count > 7) game.solution.letters[7] = 'r';
    if (game.solution.letter_count > 8) game.solution.letters[8] = 's';

    bool winner = false;
    for (int i = 0; i < game.guess_count; i ++)
    {
        printf("What is your guess #%d?\n", i + 1);

        for (int j = 0; j < game.guesses[i].letter_count; j ++)
        {
            char next_char = getchar();
            while (isspace(next_char))
            {
                next_char = getchar();
            }
            game.guesses[i].letters[j] = next_char;
        }

        for (int j = 0; j <= i; j ++)
        {
            print_guess(&game.guesses[j], &game.solution);
        }

        // If they got it correct, they win! End the game
        bool is_correct = true;
        for (int j = 0; j < game.solution.letter_count; j ++)
        {
            if (game.guesses[i].letters[j] != game.solution.letters[j])
            {
                is_correct = false;
                break;
            }
        }

        if (is_correct)
        {
            winner = true;
            break;
        }
    }

    if (winner)
    {
        printf("That's the correct word! You win!\n");
    }
    else
    {
        printf("You couldn't guess the word! You lose!\n");
    }

    return 0;
}

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void)
{
    system("/bin/sh");
}

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


#define HEADER_VAL 0xDEADBEEF
#define FOOTER_VAL 0xBAADF00D
typedef struct {
    uint64_t header;
    uint64_t size;
    char *contents;
    uint64_t footer;
} block_t;

#define MAX_BLOCKS 16
block_t block_stack[MAX_BLOCKS];
size_t block_count = 0;


#define MAX_CONTENT 256
char read_buffer[0x20];
#define NAME_SIZE 256
char player_name[NAME_SIZE];


int read_number() {

    int i = 0;
    char c;

    for (int i = 0; i < sizeof(read_buffer); i++) { read_buffer[i] = 0; }

    while (i < sizeof(read_buffer) - 1) {
        c = getchar();
        if (c == '\0' || c == '\n' || c == EOF) {
            break;
        }
        read_buffer[i++] = c;
    }

    // nothing read, return error
    if (i == 0) {
        return -1;
    }

    // Convert string to int
    int value = atoi(read_buffer);

    return value;
}


int get_index(uint64_t *index) {

    int value = read_number();
    if ((value < 0) || (value > block_count)) {
        return 0;  // Out of range
    }

    *index = value;

    return 1;
}


void read_block(uint64_t i, block_t *block_ptr) {

    memcpy(block_ptr, block_stack + i, sizeof(block_t));

}


void make_new_block() {

    if (block_count >= MAX_BLOCKS) {
        puts("Block stack is full");
        return;
    }

    printf("Enter block size: ");
    uint64_t size = read_number();
    if ((size == 0) || (size > MAX_CONTENT)) {
        printf("Bad size: %lu\n", size);
        return;
    }

    printf("Enter %lu bytes: ", size);
    char *contents = malloc(size+1);
    memset(contents, 0, size+1);
    fread(contents, 1, size, stdin);

    block_t new_block;
    new_block.header = HEADER_VAL;
    new_block.size = size;
    new_block.contents = contents;
    new_block.footer = FOOTER_VAL;

    block_stack[block_count] = new_block;
    block_count++;
}


void delete_block() {

    uint64_t index;

    if (block_count == 0) {
        puts("No blocks to delete");
        return;
    }

    printf("Enter index of block to delete: ");
    index = read_number();

    if ((index < 0) || (index > block_count)) {
        printf("Invalid index: %lu\n", index);
        return;
    }

    // Free the contents of the block
    free(block_stack[index].contents);

    // Shift remaining blocks down
    for (size_t i = index; i < block_count - 1; i++) {
        block_stack[i] = block_stack[i + 1];
    }

    block_count--;
}

void print_block_content() {

    uint64_t i;
    block_t local_block;

    printf("Index to print: ");
    if (get_index(&i)) {
        read_block(i, &local_block);
        printf("contents: %s\n", local_block.contents);
    }
}

void print_block() {

    uint64_t i;
    block_t *cur_block;

    printf("Index to print block for: ");
    if (get_index(&i) < block_count) {

        cur_block = block_stack + i;
        printf("header: 0x%lx\n", cur_block->header);
        printf("size: 0x%lx\n", cur_block->size);
        printf("contents: %p\n", cur_block->contents);
        printf("footer: 0x%lx\n", cur_block->footer);
    }

}

void edit_block() {

    uint64_t i;
    block_t local_block;

    printf("Index to edit: ");
    if (get_index(&i)) {
        local_block = block_stack[i];
    }

    if ((local_block.header == HEADER_VAL) && (local_block.footer == FOOTER_VAL)) {

        printf("Provide %ld new bytes: ", local_block.size);

        // TODO: do a direct fread?
        char *tmp = malloc(local_block.size);
        size_t bytes_read = fread(tmp, 1, local_block.size, stdin);

        for (int i=0; i < bytes_read; i++) {
            local_block.contents[i] = tmp[i];
        }

        free(tmp);
    }

}

void read_buf(char *buf, size_t size) {
    int i = 0;
    char c;

    while (i < size - 1) {
        c = getchar();
        if (c == '\n') {
            buf[i] = 0;
            break;
        }
        buf[i++] = c;
    }
}

void change_name() {

    int x = 0;
    char name_buf[NAME_SIZE];

    printf("Enter new name (end with newline): ");
    read_buf(name_buf, sizeof(name_buf));

    while ((x < NAME_SIZE - 1) && (name_buf[x])) {
        player_name[x] = name_buf[x];
        x++;
    }
}


int main(int argc, char** argv, char** envp) {

    init();

    char input[5] = { 0 };
    char *p;

    strcpy(player_name, "PLAYER");

    while (1) {

        printf("Welcome %s.\n", player_name);
        puts("Menu:");
        puts("  0: Create new block");
        puts("  1: Delete block");
        puts("  2: Print block contents");
        puts("  3: Print block size");
        puts("  4: Edit block");
        puts("  5: Change name");
        puts("Send 4 bytes, you may invoke multiple commands");
        printf("input? ");

        for (int i = 0; i < sizeof(input); i++) { input[i] = 0; }

        int bytes_read = fread(input, 1, 4, stdin);
        if (bytes_read == 0) {
            break;
        }

        p = input;
        while(*p) {

            // switch input
            switch(*p) {
                case '0':
                    make_new_block();
                    break;
                case '1':
                    delete_block(); // uses read_number to set i
                    break;
                case '2':
                    print_block_content(); // only place memcpy is called (GOT)
                    break;
                case '3':
                    print_block(); // has bad check on i
                    break;
                case '4':
                    edit_block(); // same bad check on i but validates header/footer
                    break;
                case '5':
                    change_name(); // allows arbitrary write to stack data
                    break;
                default:
                    ;
            }

            p++;
        }

    }


    puts("Bye!");

    return 0;
}

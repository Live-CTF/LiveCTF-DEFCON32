#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_PATH 260


void win(void) {
    system("/bin/sh");
}

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


int read_input(char *buf, size_t size) {

    int i = 0;
    char c;

    memset(buf, 0, size);

    while (i < size - 1) {

        c = getchar();
        if (c == '\0' || c == '\n' || c == EOF) {
            break;
        }
        buf[i++] = c;
    }
    // include null terminator in size
    i++;

    return i;
}


// Modified from http://www.phreedom.org/blog/2008/decompiling-ms08-067/
int canonicalize(char* path, int path_size) {
    char* p;
    char* q;
    char* previous_slash = NULL;
    char* current_slash  = NULL;
    char  ch;

    int len = strlen(path);
    char* end_of_path = path + len;

    // If the path starts with a server name, skip it

    if ((path[0] == '\\' || path[0] == '/') &&
        (path[1] == '\\' || path[1] == '/'))
    {
        p = path+1;

        while (*p != '\\' && *p != '/') {
            if (*p == '\0')
                return 0;
            p++;
        }

        p++;

        // make path point after the server name

        path = p;

        // make sure the server name is followed by a single slash

        if (path[0] == '\\' || path[0] == '/')
            return 0;
    }

    if (path[0] == '\0')   // return if the path is empty
        return 1;

    /* Iterate through the path and canonicalize ..\ and .\  */

    p = path;

    while (1) {
        if (*p == '\\') {
            // we have a slash

            if (current_slash == p-1)   // don't allow consequtive slashes
                return 0;

            // store the locations of the current and previous slashes

            previous_slash = current_slash;
            current_slash = p;
        }
        else if (*p == '.' && (current_slash == p-1 || p == path)) {
            // we have \. or ^.

            if (p[1] == '.' && (p[2] == '\\' || p[2] == '\0')) {
                // we have a \..\, \..$, ^..\ or ^..$ sequence

                if (previous_slash == NULL)
                    return 0;

                // example: aaa\bbb\..\ccc
                //             ^   ^  ^
                //             |   |  &p[2]
                //             |   |
                //             |   current_slash
                //             |
                //             previous_slash

                ch = p[2];

                if (previous_slash >= end_of_path)
                    return 0;

                strncpy(previous_slash, p+2, end_of_path-previous_slash);

                if (ch == '\0')
                    return 1;

                current_slash = previous_slash;
                p = previous_slash;

                // find the slash before p

                // BUG: if previous_slash points to the beginning of the
                // string, we'll go beyond the start of the buffer

                /* example string: \a\..\ */

                q = p-1;
                
                while (*q != '\\' && q != path)
                    q--;

                if (*p == '\\')
                    previous_slash = q;
                else
                    previous_slash = NULL;
            }
            else if (p[1] == '\\') {
                // we have \.\ or "^.\ "
                //

                if (current_slash != NULL) {
                    if (current_slash >= end_of_path)
                        return 0;
                    strncpy(current_slash, p+2, end_of_path-current_slash);
                    goto end_of_loop;
                }
                else {  // current_slash == NULL
                    if (p >= end_of_path)
                        return 0;
                    strncpy(p, p+2, end_of_path-p);
                    goto end_of_loop;
                }
            }
            else if (p[1] != '\0') {
                // we have \. or ^. followed by some other char

                if (current_slash != NULL) {
                    p = current_slash;
                }
                *p = '\0';
                return 1;
            }
        }

        p++;

end_of_loop:
        if (*p == '\0')
            return 1;
    }
}


int read_target(char *path_buf, int path_size) {
    char target_buf[MAX_PATH] = { 0 };

    printf("target? ");
    int bytes_read = read_input(target_buf, sizeof(target_buf));
    if (bytes_read <= 0) {
        return 0;
    }

    if(!canonicalize(path_buf, bytes_read)) {
        printf("%s/%s\n", target_buf, path_buf);
        return 1;
    } else {
        printf("Bad path");
        return 0;
    }

}


int read_path() {

    char path_buf[MAX_PATH] = { 0 };

    printf("path? ");
    int bytes_read = read_input(path_buf, MAX_PATH);
    if (bytes_read <= 0) {
        return 0;
    }

    return read_target(path_buf, bytes_read);
}



void handle_input() {

    int keep_going = 0;
    do {
        keep_going = read_path();
    } while (keep_going);

}

int main(int argc, char** argv, char** envp)
{
    init();

    handle_input();

    return 0;
}

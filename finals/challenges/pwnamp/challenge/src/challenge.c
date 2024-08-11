#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    char *title;
    char *artist;
    int year;
} song;

typedef int (*song_comparer)(song *a, song *b);

typedef struct
{
    song_comparer comparer;
    size_t max_songs;
    char *name;
    ssize_t songs[]; // malloc( sizeof(struct) + array_len*sizeof(array element) )
} playlist;

typedef uint16_t node_t;

#define MAX_SONGS (1 << 14)
#define MAX_PLAYLISTS 32
song *library[MAX_SONGS] = {0};
playlist *playlists[MAX_PLAYLISTS] = {0};

int sorter_artist(song *a, song *b)
{
    return strcmp(a->artist, b->artist);
}

int sorter_title(song *a, song *b)
{
    return strcmp(a->title, b->title);
}

int sorter_year(song *a, song *b)
{
    return a->year - b->year;
}

void tree_insert(uint16_t* tree, size_t idx, song_comparer comparer, size_t song_idx, bool do_insert) {
    uint16_t cur_node = tree[idx];
    uint16_t lib_idx = cur_node >> 2;
    uint8_t has_left = (cur_node >> 1) & 1;
    uint8_t has_right = (cur_node >> 0) & 1;

    //printf("DEBUG: idx=%ld, cur_node=%x, lib_idx=%d, new_idx=%ld\n", idx, cur_node, lib_idx, song_idx);

    if(do_insert) {
        //printf("[DEBUG]: *%p/%#lx = %lx\n", &tree[idx], idx, (song_idx << 2) | (0 << 1) | (0 << 0));
        tree[idx] = (song_idx << 2) | (0 << 1) | (0 << 0);
        return;
    }
    song*cur_song = library[lib_idx];
    song*new_song = library[song_idx];
    
    //printf("[DEBUG]: cur[%d]=%p, new[%ld]=%p\n", lib_idx, cur_song, song_idx, new_song);
    
    if(comparer(cur_song, new_song) > 0) {
        tree[idx] |= (1 << 1);
        //printf("DEBUG: left\n");
        tree_insert(tree, 2*idx+1, comparer, song_idx, !has_left);
    } else {
        tree[idx] |= (1 << 0);
        //printf("DEBUG: right\n");
        tree_insert(tree, 2*idx+2, comparer, song_idx, !has_right);
    }
}

void tree_song_print(uint16_t* tree, size_t idx) {
    uint16_t cur_node = tree[idx];
    uint16_t lib_idx = cur_node >> 2;
    uint8_t has_left = (cur_node >> 1) & 1;
    uint8_t has_right = (cur_node >> 0) & 1;

    if(lib_idx == 0x3FFF) {
        return;
    }

    //printf("DEBUG: idx=%ld, node=%x, lib_idx=%d, L=%d, R=%d\n", idx, cur_node, lib_idx, has_left, has_right);

    if(has_left) {
        //printf("DEBUG: left\n");
        tree_song_print(tree, 2*idx+1);
    }
    song *song = library[lib_idx];
    printf("%s - %s [%d]\n", song->artist, song->title, song->year);
    if(has_right) {
        //printf("DEBUG: right\n");
        tree_song_print(tree, 2*idx+2);
    }
}

void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    song *new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Charlie Morningstar");
    new_song->title = strdup("Happy Day in Hell");
    new_song->year = 2024; 
    library[0] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Adam");
    new_song->title = strdup("Hell is Forever");
    new_song->year = 2024;
    library[1] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Vox");
    new_song->title = strdup("Stayed Gone");
    new_song->year = 2024;
    library[2] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Charlie Morningstar");
    new_song->title = strdup("It Starts with Sorry");
    new_song->year = 2024;
    library[3] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Velvette");
    new_song->title = strdup("Respectless");
    new_song->year = 2024;
    library[4] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Carmilla Carmine");
    new_song->title = strdup("Whatever It Takes");
    new_song->year = 2024;
    library[5] = new_song;
    
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Angel Dust");
    new_song->title = strdup("Poison");
    new_song->year = 2024;
    library[6] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Husk");
    new_song->title = strdup("Loser, Baby");
    new_song->year = 2024;
    library[7] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Lucifer Morningstar");
    new_song->title = strdup("Hell's Greatest Dad");
    new_song->year = 2024;
    library[8] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Lucifer Morningstar");
    new_song->title = strdup("More Than Anything");
    new_song->year = 2024;
    library[9] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Saint Peter");
    new_song->title = strdup("Welcome to Heaven");
    new_song->year = 2024;
    library[10] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Emily");
    new_song->title = strdup("You Didn't Know");
    new_song->year = 2024;
    library[11] = new_song;

    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Carmilla Carmine");
    new_song->title = strdup("Out for Love");
    new_song->year = 2024;
    library[12] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Charlie Morningstar");
    new_song->title = strdup("Ready for This");
    new_song->year = 2024;
    library[13] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Vaggie");
    new_song->title = strdup("More Than Anything (Reprise)");
    new_song->year = 2024;
    library[14] = new_song;
    
    new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); exit(1); }
    new_song->artist = strdup("Hazbin Hotel Cast");
    new_song->title = strdup("Finale");
    new_song->year = 2024;
    library[15] = new_song;

    playlist* new_playlist = malloc(sizeof(playlist) + 16*sizeof(ssize_t));
    if(new_playlist == NULL) { puts("Failed to allocate playlist"); exit(1); }
    new_playlist->name = strdup("Hazbin Hotel Season 1");
    new_playlist->max_songs = 16;
    new_playlist->comparer = sorter_title;
    new_playlist->songs[0] = 0;
    new_playlist->songs[1] = 1;
    new_playlist->songs[2] = 2;
    new_playlist->songs[3] = 3;
    new_playlist->songs[4] = 4;
    new_playlist->songs[5] = 5;
    new_playlist->songs[6] = 6;
    new_playlist->songs[7] = 7;
    new_playlist->songs[8] = 8;
    new_playlist->songs[9] = 9;
    new_playlist->songs[10] = 10;
    new_playlist->songs[11] = 11;
    new_playlist->songs[12] = 12;
    new_playlist->songs[13] = 13;
    new_playlist->songs[14] = 14;
    new_playlist->songs[15] = 15;
    playlists[0] = new_playlist;
}

void welcome()
{
    puts("Pwnamp, pwnamp, pwnamp - It really whips the CTF");
}

void win()
{
    system("/bin/sh");
    exit(0);
}

int get_int()
{
    char *input = NULL;
    size_t input_len = 0;
    if (-1 == getline(&input, &input_len, stdin))
    {
        free(input);
        return -1;
    }

    int int_result = -1;
    int scan_res = sscanf(input, "%d", &int_result);
    free(input);
    if (scan_res != 1)
    {
        return -1;
    }
    return int_result;
}

char *get_string()
{
    char *input = NULL;
    size_t input_len = 0;
    if (-1 == getline(&input, &input_len, stdin))
    {
        free(input);
        return NULL;
    }
    input[strcspn(input, "\n")] = 0;

    return input;
}

void menu()
{
    puts("== [Pwnamp 1.0 Menu] ==");
    puts("1. List song library");
    puts("2. View song");
    puts("3. Add song");
    puts("4. Delete song");
    puts("5. List playlists");
    puts("6. Show playlist");
    puts("7. Create playlist");
    puts("8. Add song to playlist");
    puts("9. Remove song from playlist");
    puts("10. Delete playlist");
    puts("11. Exit");
}

void list_song_library()
{
    puts("Song library:");
    for (size_t i = 0; i < MAX_SONGS; i++)
    {
        song *song = library[i];
        if (song == NULL)
        {
            continue;
        }
        printf("%ld. %s - %s [%d]\n", i, song->artist, song->title, song->year);
    }
}

void view_song()
{
    printf("Song index: ");
    int song_idx = get_int();
    if (song_idx < 0 || song_idx >= MAX_SONGS)
    {
        puts("Invalid song index");
        return;
    }
    song *song = library[song_idx];
    if (song == NULL)
    {
        puts("No such song");
        return;
    }
    printf("Artist: %s\nTitle: %s\nYear: %d\n", song->artist, song->title, song->year);
}

void add_song()
{
    ssize_t free_slot = -1;
    for (size_t i = 0; i < MAX_SONGS; i++)
    {
        if (library[i] == NULL)
        {
            free_slot = i;
            break;
        }
    }
    if (free_slot == -1)
    {
        puts("Library full");
        return;
    }

    printf("Artist: ");
    char *artist = get_string();
    if (artist == NULL)
    {
        printf("Failed to get artist\n");
        return;
    }

    printf("Title: ");
    char *title = get_string();
    if (title == NULL)
    {
        printf("Failed to get title\n");
        free(artist);
        return;
    }

    printf("Year: ");
    int year = get_int();
    if (year < 0)
    {
        printf("Failed to get year\n");
        free(artist);
        free(title);
        return;
    }

    song *new_song = malloc(sizeof(song));
    if(new_song == NULL) { puts("Failed to allocate song"); return; }
    new_song->artist = artist;
    new_song->title = title;
    new_song->year = year;
    library[free_slot] = new_song;
}

void delete_song()
{
    printf("Song index: ");
    int song_idx = get_int();
    if (song_idx < 0 || song_idx >= MAX_SONGS)
    {
        puts("Invalid song index");
        return;
    }
    song *song = library[song_idx];
    if (song == NULL)
    {
        puts("No such song");
        return;
    }
    free(song->artist);
    free(song->title);
    free(song);
    library[song_idx] = NULL;
}

void list_playlists()
{
    puts("Playlists:");
    for (size_t i = 0; i < MAX_PLAYLISTS; i++)
    {
        playlist *playlist = playlists[i];
        if (playlist == NULL)
        {
            continue;
        }
        printf("%ld. %s (%ld)\n", i, playlist->name, playlist->max_songs);
    }
}

void show_playlist()
{
    printf("Playlist index: ");
    int playlist_idx = get_int();
    if (playlist_idx < 0 || playlist_idx >= MAX_PLAYLISTS)
    {
        puts("Invalid playlist index");
        return;
    }
    playlist *playlist = playlists[playlist_idx];
    if (playlist == NULL)
    {
        puts("No such playlist");
        return;
    }

    size_t sorter_count = 0x100 * playlist->max_songs;
    size_t sorter_alloc = sorter_count * sizeof(uint16_t);
    //printf("[DEBUG]: sorter chunk size: %#lx\n", sorter_alloc);
    uint16_t *sorter = malloc(sorter_alloc);
    //printf("[DEBUG]: sorter size=%#lx, ptr=%p\n", sorter_alloc, sorter);
    if(sorter == NULL) { puts("Failed to view playlist"); return; }
    for(size_t i = 0; i < sorter_count; i++) {
        sorter[i] = (0x3FFF << 2) | (0 << 1) | (0 << 0);
    }
    for(size_t i = 0; i < playlist->max_songs; i++) {
        ssize_t song_idx = playlist->songs[i];
        if(song_idx == -1) {
            continue;
        }
        if(library[song_idx] == NULL) {
            continue;
        }

        tree_insert(sorter, 0, playlist->comparer, song_idx, i==0);
    }

    printf("Playlist: %s\n", playlist->name);
    tree_song_print(sorter, 0);

    /*for (size_t i = 0; i < playlist->max_songs; i++)
    {
        ssize_t library_idx = playlist->songs[i];
        if (library_idx == -1)
        {
            continue;
        }
        song *song = library[library_idx];
        printf("%ld. %s - %s (%d)\n", i, song->artist, song->title, song->year);
    }*/
}

void create_playlist()
{
    ssize_t free_slot = -1;
    for (size_t i = 0; i < MAX_PLAYLISTS; i++)
    {
        if (playlists[i] == NULL)
        {
            free_slot = i;
            break;
        }
    }
    if (free_slot == -1)
    {
        puts("Playlists full");
        return;
    }

    printf("Playlist name: ");
    char *playlist_name = get_string();
    if (playlist_name == NULL)
    {
        printf("Failed to get playlist name\n");
        return;
    }

    printf("Size: ");
    int playlist_size = get_int();
    if (playlist_size < 0)
    {
        printf("Failed to get size\n");
        free(playlist_name);
        return;
    }

    int sort_method = -1;
    while (true)
    {
        puts("Sort playlist by:");
        puts("1. Title");
        puts("2. Artist");
        puts("3. Year");
        printf("> ");
        int choice = get_int();
        if (choice >= 1 && choice <= 3)
        {
            sort_method = choice;
            break;
        }
        else
        {
            puts("Invalid sort method");
        }
    }

    size_t playlist_alloc = sizeof(playlist) + playlist_size * sizeof(ssize_t);
    //printf("[DEBUG]: playlist chunk size: %#lx\n", playlist_alloc);
    playlist *new_playlist = malloc(playlist_alloc);
    //printf("[DEBUG]: playlist size=%#lx, ptr=%p\n", playlist_alloc, new_playlist);
    new_playlist->max_songs = playlist_size;
    for (size_t i = 0; i < new_playlist->max_songs; i++)
    {
        new_playlist->songs[i] = -1;
    }
    new_playlist->name = playlist_name;
    switch (sort_method)
    {
    case 1:
        new_playlist->comparer = sorter_title;
        break;
    case 2:
        new_playlist->comparer = sorter_artist;
        break;
    case 3:
        new_playlist->comparer = sorter_year;
        break;
    default:
        puts("Invalid sorting");
        free(new_playlist);
        return;
        break;
    }

    playlists[free_slot] = new_playlist;
}

void add_song_to_playlist()
{
    printf("Song index: ");
    int song_idx = get_int();
    if (song_idx < 0 || song_idx >= MAX_SONGS)
    {
        puts("Invalid song index");
        return;
    }
    song *song = library[song_idx];
    if (song == NULL)
    {
        puts("No such song");
        return;
    }

    printf("Playlist index: ");
    int playlist_idx = get_int();
    if (playlist_idx < 0 || playlist_idx >= MAX_PLAYLISTS)
    {
        puts("Invalid playlist index");
        return;
    }
    playlist *playlist = playlists[playlist_idx];
    if (playlist == NULL)
    {
        puts("No such playlist");
        return;
    }

    ssize_t free_slot = -1;
    for (size_t i = 0; i < playlist->max_songs; i++)
    {
        if (playlist->songs[i] == -1)
        {
            free_slot = i;
            break;
        }
    }
    if (free_slot == -1)
    {
        puts("Playlist already full");
        return;
    }

    playlist->songs[free_slot] = song_idx;
}

void remove_song_from_playlist()
{
    printf("Playlist index: ");
    int playlist_idx = get_int();
    if (playlist_idx < 0 || playlist_idx >= MAX_PLAYLISTS)
    {
        puts("Invalid playlist index");
        return;
    }
    playlist *playlist = playlists[playlist_idx];
    if (playlist == NULL)
    {
        puts("No such playlist");
        return;
    }

    printf("Song index: ");
    int song_idx = get_int();
    if (song_idx < 0 || song_idx >= playlist->max_songs)
    {
        puts("Invalid song index");
        return;
    }
    ssize_t song_library_idx = playlist->songs[song_idx];
    if (song_library_idx == -1)
    {
        puts("No such song in playlist");
        return;
    }

    playlist->songs[song_idx] = -1;
}

void delete_playlist()
{
    printf("Playlist index: ");
    int playlist_idx = get_int();
    if (playlist_idx < 0 || playlist_idx >= MAX_PLAYLISTS)
    {
        puts("Invalid playlist index");
        return;
    }
    playlist *playlist = playlists[playlist_idx];
    if (playlist == NULL)
    {
        puts("No such playlist");
        return;
    }

    free(playlist);
    playlists[playlist_idx] = NULL;
}

int main()
{
    init();
    welcome();

    int running = 1;
    while (running)
    {
        menu();
        printf("> ");
        int choice = get_int();
        switch (choice)
        {
        case 1:
            list_song_library();
            break;
        case 2:
            view_song();
            break;
        case 3:
            add_song();
            break;
        case 4:
            delete_song();
            break;
        case 5:
            list_playlists();
            break;
        case 6:
            show_playlist();
            break;
        case 7:
            create_playlist();
            break;
        case 8:
            add_song_to_playlist();
            break;
        case 9:
            remove_song_from_playlist();
            break;
        case 10:
            delete_playlist();
            break;
        case 11:
            puts("Goodbye!");
            running = 0;
            break;

        default:
            puts("Invalid choice");
            break;
        }
    }
}

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>

#include <seccomp.h>

#include <linux/seccomp.h>

#define SHELLCODE_LEN 0x1000

pthread_mutex_t thread_init_lock;
pthread_mutex_t thread_body_lock;

pthread_mutex_t thread_input_lock;

int input_exit_clean = 0;


void win()
{
    system("/bin/sh");
}


void thread_task()
{
    // init done, unlock mutex
    pthread_mutex_unlock(&thread_init_lock);

    // Wait for the body mutex to be unlocked
    pthread_mutex_lock(&thread_body_lock);
    puts("Nice try :>");
}


void do_shellcode(void* addr)
{
    if (read(0, addr, SHELLCODE_LEN) == -1)
    {
        puts("Read failed");
        exit(1);
    }

    (*(void(*)()) addr)();
}


void take_input()
{
    void* shellcode = aligned_alloc(0x1000, SHELLCODE_LEN);
    if (shellcode == NULL)
    {
        printf("Map failed: %d\n", errno);
        exit(1);
    }

    if (mprotect(shellcode, SHELLCODE_LEN, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
    {
        puts("mprotect failed");
        exit(1);
    }

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_load(ctx);

    do_shellcode(shellcode);

    input_exit_clean = 1;
    pthread_mutex_unlock(&thread_input_lock);
}


pthread_t cursed(void* mystack, size_t mystacksize)
{
    int rc;
    void* stackaddr;
    size_t stacksize;
    pthread_attr_t attr;

    if (pthread_attr_init(&attr) == -1)
    {
        perror("error in pthread_attr_init");
        exit(1);
    }

    rc = pthread_attr_setstack(&attr, mystack, mystacksize);
    if (rc != 0) {
        printf("pthread_attr_setstack: %d\n", rc);
        exit(1);
    }

    rc = pthread_attr_getstack(&attr, &stackaddr, &stacksize);
    if (rc != 0) {
        printf("pthread_attr_getstack: %d\n", rc);
        exit(1);
    }

    // Take both mutexes
    pthread_mutex_lock(&thread_init_lock);
    pthread_mutex_lock(&thread_body_lock);

    pthread_t thread;
    rc = pthread_create(&thread, &attr, (void*)&thread_task, NULL);
    if (rc != 0)
    {
        printf("pthread_create: %d\n", rc);
        exit(1);
    }
    return thread;
}


int main(void)
{
    const size_t stack_size = 0x4000;
    void* stack = aligned_alloc(0x1000, stack_size); //mmap(NULL, mystacksize+0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    pthread_t thread = cursed(stack, stack_size);

    // Wait for thread init to be done
    pthread_mutex_lock(&thread_init_lock);

    pthread_mutex_lock(&thread_input_lock);

    // Start thread to take and run shellcode
    pthread_t input_thread;
    int rc = pthread_create(&input_thread, NULL, (void*)&take_input, NULL);
    if (rc != 0)
    {
        printf("pthread_create: %d\n", rc);
        exit(1);
    }

    rc = pthread_join(input_thread, NULL);
    if (rc != 0)
    {
        printf("pthread_join: %d\n", rc);
        exit(1);
    }

    if (input_exit_clean != 1)
    {
        puts("input thread failed to exit cleanly");
        exit(1);
    }

    // Wait until input thread is done
    pthread_mutex_lock(&thread_input_lock);
    // Let thread run body
    pthread_mutex_unlock(&thread_body_lock);

    pthread_join(thread, NULL);

    exit(0);
}

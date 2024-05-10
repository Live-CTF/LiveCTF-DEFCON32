// gcc -o challenge -Os -Wl,-z,norelro ./challenge.c -lseccomp

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/utsname.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <sys/prctl.h>

#define ALARM_TIME 10000

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

uint64_t read_int(const char* message)
{
    uint64_t result;
    printf("%s\n", message);
    int _ = scanf("%" SCNx64, &result);
    (void)_; // hush, gcc
    return result;
}

void map_and_seccomp()
{
    mprotect((void*)((uintptr_t)(void*)&init & ~0xFFF), 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC);
 
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_load(ctx);
}

int child()
{
    map_and_seccomp();

    for (int i = 0; i < ALARM_TIME * 1000; i++)
    {
        usleep(1000);
    }
    return 0;
}

uint64_t readv_helper(pid_t pid, uint64_t address)
{
    uint64_t result;

    struct iovec local;
    local.iov_base = &result;
    local.iov_len = sizeof(uint64_t);

    struct iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = sizeof(uint64_t);

    ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    // Bug: If process_vm_readv fails it will simply not overwrite the bytes in result
    // We're just ignoring the return value here so you _will_ get to see this 
    (void)nread;

    return result;
}

void writev_helper(pid_t pid, uint64_t address, uint64_t value)
{
    struct iovec local;
    local.iov_base = &value;
    local.iov_len = sizeof(uint64_t);

    struct iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = sizeof(uint64_t);

    ssize_t nwrite = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    // Don't really care about checking this
    (void)nwrite;
}

int parent(pid_t child_pid)
{
    int run = 1;
    puts("process_vm_readv-me-maybe");
    puts("In the increasingly less obvious-what-the-pun-was series");

    while (run)
    {
        puts("Menu:");
        puts("1. process_vm_readv");
        puts("2. process_vm_writev");
        puts("3. exit");

        uint64_t choice = read_int("Choice: ");

        switch (choice)
        {
        case 1:
        {
            printf("Value: %" PRIx64 "\n", readv_helper(child_pid, read_int("Address: ")));
            break;
        }
        case 2:
        {
            writev_helper(child_pid, read_int("Address: "), read_int("Value: "));
            break;
        }
        case 3:
            run = 0;
            break;
        }
    }

    kill(child_pid, SIGKILL);
}

int main(int argc, char** argv, char** envp)
{
    init();
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    pid_t child_pid = fork();
    if (child_pid == 0) {
        return child();
    }

    return parent(child_pid);
}

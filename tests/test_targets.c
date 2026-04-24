#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <1-6>\n", argv[0]); return 1; }
    int test = atoi(argv[1]);
    switch (test) {
        case 1: {
            int fd = open("/etc/passwd", O_RDONLY);
            printf("[TEST 1] /etc/passwd fd=%d\n", fd); if (fd>=0) close(fd);
            fd = open("/etc/shadow", O_RDONLY);
            printf("[TEST 1] /etc/shadow fd=%d\n", fd); if (fd>=0) close(fd);
            break;
        }
        case 2: {
            for (int i = 0; i < 25; i++) {
                pid_t p = fork(); if (p == 0) _exit(0); else if (p > 0) wait(NULL);
            }
            break;
        }
        case 3: {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            printf("[TEST 3] socket fd=%d\n", s); if (s>=0) close(s);
            break;
        }
        case 4:
            printf("[TEST 4] setuid(0) = %d\n", setuid(0));
            break;
        case 5: {
            void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (m != MAP_FAILED) {
                printf("[TEST 5] mprotect(RWX) = %d\n",
                       mprotect(m, 4096, PROT_READ|PROT_WRITE|PROT_EXEC));
                munmap(m, 4096);
            }
            break;
        }
        case 6: {
            int fd = open("/tmp/ids_test_file", O_CREAT|O_WRONLY, 0644);
            if (fd >= 0) { close(fd); unlink("/tmp/ids_test_file"); }
            printf("[TEST 6] done\n");
            break;
        }
        default: printf("Unknown test %d\n", test); return 1;
    }
    printf("[TEST %d] Done.\n", test);
    return 0;
}

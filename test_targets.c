/*
 * test_targets.c - Programs to test the IDS monitor
 *
 * Compile: gcc -Wall test_targets.c -o test_targets
 * Usage:   sudo ./ids_monitor ./test_targets <test_number>
 *
 * Tests:
 *   1 - read /etc/passwd  (sensitive file access)
 *   2 - fork many times   (fork bomb simulation)
 *   3 - create a socket   (network activity)
 *   4 - try setuid(0)     (privilege escalation)
 *   5 - mprotect W+X      (shellcode simulation)
 *   6 - delete /tmp file  (log tampering simulation)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <test_number 1-6>\n", argv[0]);
        return 1;
    }

    int test = atoi(argv[1]);

    switch (test) {
        /* ── TEST 1: Sensitive file access ─── */
        case 1: {
            printf("[TEST 1] Attempting to open /etc/passwd...\n");
            int fd = open("/etc/passwd", O_RDONLY);
            if (fd >= 0) {
                printf("[TEST 1] Opened /etc/passwd (fd=%d)\n", fd);
                close(fd);
            } else {
                printf("[TEST 1] Open failed (permission denied)\n");
            }

            printf("[TEST 1] Attempting to open /etc/shadow...\n");
            fd = open("/etc/shadow", O_RDONLY);
            if (fd >= 0) {
                printf("[TEST 1] Opened /etc/shadow (fd=%d)\n", fd);
                close(fd);
            } else {
                printf("[TEST 1] /etc/shadow open failed\n");
            }
            break;
        }

        /* ── TEST 2: Fork bomb simulation ─── */
        case 2: {
            printf("[TEST 2] Forking 25 times to simulate fork bomb...\n");
            for (int i = 0; i < 25; i++) {
                pid_t p = fork();
                if (p == 0) {
                    /* child exits immediately — this is just to trigger the counter */
                    exit(0);
                } else if (p > 0) {
                    wait(NULL);
                }
            }
            printf("[TEST 2] Fork loop done.\n");
            break;
        }

        /* ── TEST 3: Socket creation ─── */
        case 3: {
            printf("[TEST 3] Creating a TCP socket...\n");
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                printf("[TEST 3] Socket created (fd=%d)\n", sock);
                close(sock);
            } else {
                printf("[TEST 3] Socket creation failed\n");
            }
            break;
        }

        /* ── TEST 4: Privilege escalation ─── */
        case 4: {
            printf("[TEST 4] Attempting setuid(0) (requires root to succeed)...\n");
            int ret = setuid(0);
            printf("[TEST 4] setuid(0) returned %d\n", ret);
            break;
        }

        /* ── TEST 5: mprotect WRITE+EXEC (shellcode pattern) ─── */
        case 5: {
            printf("[TEST 5] Allocating RWX memory page...\n");
            void *mem = mmap(NULL, 4096,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem == MAP_FAILED) {
                printf("[TEST 5] mmap failed\n");
                break;
            }
            /* now make it executable — this is what shellcode injectors do */
            int ret = mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
            printf("[TEST 5] mprotect(RWX) returned %d\n", ret);
            munmap(mem, 4096);
            break;
        }

        /* ── TEST 6: Delete /tmp file (log tampering simulation) ─── */
        case 6: {
            printf("[TEST 6] Creating then deleting /tmp/ids_test_file...\n");
            int fd = open("/tmp/ids_test_file", O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) {
                close(fd);
                unlink("/tmp/ids_test_file");
                printf("[TEST 6] File deleted.\n");
            }
            break;
        }

        default:
            printf("Unknown test number: %d (use 1-6)\n", test);
            return 1;
    }

    printf("[TEST %d] Done.\n", test);
    return 0;
}

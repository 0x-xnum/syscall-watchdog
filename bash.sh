#!/bin/bash
set -e

# ── Run this from inside your cloned repo ──────────────────
# cd /path/to/syscall-watchdog
# bash setup.sh

echo "[1/7] Creating folder structure..."
mkdir -p src include tests

echo "[2/7] Removing old file..."
rm -f ids_monitor.c test_targets.c

echo "[3/7] Writing source files..."

# ── include/logger.h ───────────────────────────────────────
cat > include/logger.h << 'EOF'
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

int  logger_init(const char *path);
void logger_close(void);
void log_alert(const char *fmt, ...);
void log_info(const char *fmt, ...);

#endif /* LOGGER_H */
EOF

# ── include/syscall_filter.h ───────────────────────────────
cat > include/syscall_filter.h << 'EOF'
#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <sys/types.h>
#include <sys/user.h>

const char *get_syscall_name(long num);
int is_sensitive_file(const char *path);
int is_always_suspicious(const char *prog);
int is_shell(const char *prog);
void read_string_from_tracee(pid_t pid, long addr, char *buf, size_t size);
void check_syscall(pid_t pid, struct user_regs_struct *regs);
void check_fork_bomb(pid_t pid);

#endif /* SYSCALL_FILTER_H */
EOF

# ── include/monitor.h ──────────────────────────────────────
cat > include/monitor.h << 'EOF'
#ifndef MONITOR_H
#define MONITOR_H

#include <sys/types.h>

#define MAX_PIDS 256

extern pid_t watched_pids[MAX_PIDS];
extern int   watched_count;

void add_pid(pid_t pid);
void remove_pid(pid_t pid);
int  monitor_run(int argc, char **argv);

#endif /* MONITOR_H */
EOF

# ── src/logger.c ───────────────────────────────────────────
cat > src/logger.c << 'EOF'
#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "logger.h"

static FILE *log_fp = NULL;

int logger_init(const char *path) {
    log_fp = fopen(path, "a");
    return log_fp ? 0 : -1;
}

void logger_close(void) {
    if (log_fp) { fclose(log_fp); log_fp = NULL; }
}

static void write_log(const char *level, const char *color,
                      const char *fmt, va_list args) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(stderr, "%s[%-5s %s]\033[0m ", color, level, timebuf);
    va_list args_copy;
    va_copy(args_copy, args);
    vfprintf(stderr, fmt, args_copy);
    va_end(args_copy);
    fprintf(stderr, "\n");

    if (log_fp) {
        fprintf(log_fp, "[%-5s %s] ", level, timebuf);
        vfprintf(log_fp, fmt, args);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
}

void log_alert(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log("ALERT", "\033[1;31m", fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log("INFO", "\033[0;36m", fmt, args);
    va_end(args);
}
EOF

# ── src/syscall_filter.c ───────────────────────────────────
cat > src/syscall_filter.c << 'EOF'
#define _POSIX_C_SOURCE 200112L

#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <syscall.h>

#include "syscall_filter.h"
#include "logger.h"

#define FORK_BOMB_LIMIT 20
#define MAX_PATH_LEN    256

typedef struct { long number; const char *name; } SyscallEntry;

static const SyscallEntry syscall_names[] = {
    { SYS_read,     "read"     }, { SYS_write,    "write"    },
    { SYS_open,     "open"     }, { SYS_openat,   "openat"   },
    { SYS_close,    "close"    }, { SYS_execve,   "execve"   },
    { SYS_fork,     "fork"     }, { SYS_clone,    "clone"    },
    { SYS_socket,   "socket"   }, { SYS_connect,  "connect"  },
    { SYS_bind,     "bind"     }, { SYS_listen,   "listen"   },
    { SYS_setuid,   "setuid"   }, { SYS_setgid,   "setgid"   },
    { SYS_ptrace,   "ptrace"   }, { SYS_kill,     "kill"     },
    { SYS_unlink,   "unlink"   }, { SYS_chmod,    "chmod"    },
    { SYS_chown,    "chown"    }, { SYS_mmap,     "mmap"     },
    { SYS_mprotect, "mprotect" }, { -1,           "unknown"  }
};

const char *get_syscall_name(long num) {
    for (int i = 0; syscall_names[i].number != -1; i++)
        if (syscall_names[i].number == num)
            return syscall_names[i].name;
    return "unknown";
}

static const char *sensitive_files[] = {
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/.ssh", "/root/.bash_history", "/.ssh/id_rsa",
    "/etc/crontab", "/var/log/auth.log", NULL
};

int is_sensitive_file(const char *path) {
    for (int i = 0; sensitive_files[i]; i++)
        if (strstr(path, sensitive_files[i])) return 1;
    return 0;
}

static const char *always_suspicious[] = { "nc", "ncat", "netcat", NULL };
static const char *shell_names[]       = { "bash", "sh", "zsh", "python", "perl", "ruby", NULL };

int is_always_suspicious(const char *prog) {
    for (int i = 0; always_suspicious[i]; i++)
        if (strstr(prog, always_suspicious[i])) return 1;
    return 0;
}

int is_shell(const char *prog) {
    for (int i = 0; shell_names[i]; i++)
        if (strstr(prog, shell_names[i])) return 1;
    return 0;
}

void read_string_from_tracee(pid_t pid, long addr, char *buf, size_t size) {
    size_t i = 0;
    while (i < size - 1) {
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), 0);
        if (word == -1) break;
        char *bytes = (char *)&word;
        for (int b = 0; b < 8 && i < size - 1; b++, i++) {
            buf[i] = bytes[b];
            if (bytes[b] == '\0') goto done;
        }
    }
done:
    buf[i] = '\0';
}

static int fork_count = 0;

void check_fork_bomb(pid_t pid) {
    fork_count++;
    if (fork_count > FORK_BOMB_LIMIT) {
        log_alert("PID %d FORK BOMB detected! fork/clone called %d times — KILLING process",
                  pid, fork_count);
        kill(pid, SIGKILL);
        log_info("PID %d has been killed by IDS.", pid);
    }
}

static void check_socket(pid_t pid, struct user_regs_struct *regs) {
    int domain = (int)regs->rdi;
    if (domain == AF_INET || domain == AF_INET6)
        log_alert("PID %d opened an INTERNET SOCKET (domain=%d) — possible C2 or data exfiltration",
                  pid, domain);
    else
        log_info("PID %d created a local socket (domain=%d) — not suspicious", pid, domain);
}

void check_syscall(pid_t pid, struct user_regs_struct *regs) {
    long nr = regs->orig_rax;
    char path[MAX_PATH_LEN];

    if (nr == SYS_open || nr == SYS_openat) {
        path[0] = '\0';
        long addr = (nr == SYS_openat) ? (long)regs->rsi : (long)regs->rdi;
        read_string_from_tracee(pid, addr, path, sizeof(path));
        if (is_sensitive_file(path))
            log_alert("PID %d tried to open SENSITIVE file: %s", pid, path);
    }
    else if (nr == SYS_execve) {
        char prog[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, prog, sizeof(prog));
        log_info("PID %d called execve(\"%s\")", pid, prog);
        if (is_always_suspicious(prog)) {
            log_alert("PID %d spawning ALWAYS-SUSPICIOUS program: %s", pid, prog);
        } else if (is_shell(prog)) {
            char arg1[MAX_PATH_LEN] = {0};
            long second_ptr = ptrace(PTRACE_PEEKDATA, pid,
                                     (void *)((long)regs->rsi + sizeof(char *)), 0);
            if (second_ptr)
                read_string_from_tracee(pid, second_ptr, arg1, sizeof(arg1));
            if (strcmp(arg1, "-c") == 0 || strcmp(arg1, "-i") == 0)
                log_alert("PID %d spawning INTERACTIVE/INLINE shell: %s %s — likely malicious",
                          pid, prog, arg1);
            else
                log_info("PID %d running shell/interpreter with script: %s — probably ok", pid, prog);
        }
    }
    else if (nr == SYS_fork || nr == SYS_clone) { check_fork_bomb(pid); }
    else if (nr == SYS_socket)                   { check_socket(pid, regs); }
    else if (nr == SYS_setuid) {
        if ((int)regs->rdi == 0)
            log_alert("PID %d called setuid(0) — PRIVILEGE ESCALATION attempt!", pid);
    }
    else if (nr == SYS_setgid) {
        if ((int)regs->rdi == 0)
            log_alert("PID %d called setgid(0) — PRIVILEGE ESCALATION attempt!", pid);
    }
    else if (nr == SYS_ptrace) {
        log_alert("PID %d called ptrace() — possible ANTI-DEBUG or process injection attempt!", pid);
    }
    else if (nr == SYS_unlink) {
        path[0] = '\0';
        read_string_from_tracee(pid, (long)regs->rdi, path, sizeof(path));
        if (strstr(path, "/var/log") || strstr(path, "/tmp"))
            log_alert("PID %d deleting suspicious file: %s", pid, path);
    }
    else if (nr == SYS_mprotect) {
        int prot = (int)regs->rdx;
        if ((prot & 0x4) && (prot & 0x2))
            log_alert("PID %d called mprotect(PROT_WRITE|PROT_EXEC) — possible SHELLCODE injection!", pid);
    }
}
EOF

# ── src/monitor.c ──────────────────────────────────────────
cat > src/monitor.c << 'EOF'
#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "monitor.h"
#include "syscall_filter.h"
#include "logger.h"

pid_t watched_pids[MAX_PIDS];
int   watched_count = 0;

void add_pid(pid_t pid) {
    if (watched_count < MAX_PIDS)
        watched_pids[watched_count++] = pid;
}

void remove_pid(pid_t pid) {
    for (int i = 0; i < watched_count; i++) {
        if (watched_pids[i] == pid) {
            watched_pids[i] = watched_pids[--watched_count];
            return;
        }
    }
}

static pid_t traced_pid = -1;

static void handle_sigint(int sig) {
    (void)sig;
    log_info("IDS shutting down (SIGINT received).");
    logger_close();
    if (traced_pid > 0) ptrace(PTRACE_DETACH, traced_pid, 0, 0);
    _exit(0);
}

static void set_trace_options(pid_t pid) {
    ptrace(PTRACE_SETOPTIONS, pid, 0,
           PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK |
           PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
}

int monitor_run(int argc, char **argv) {
    (void)argc;
    signal(SIGINT, handle_sigint);

    log_info("IDS started. Monitoring: %s", argv[1]);
    fprintf(stderr,
            "\033[1;33m[IDS] Monitoring '%s' — alerts will appear in red\033[0m\n\n",
            argv[1]);

    pid_t pid = fork();
    if (pid == -1) return -1;

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], argv + 1);
        fprintf(stderr, "[IDS FATAL] execvp failed: %s\n", strerror(errno));
        _exit(1);
    }

    traced_pid = pid;
    add_pid(pid);
    waitpid(pid, 0, 0);
    set_trace_options(pid);

    int fork_clone_total = 0;

    for (;;) {
        for (int i = 0; i < watched_count; i++)
            ptrace(PTRACE_SYSCALL, watched_pids[i], 0, 0);

        int status;
        pid_t stopped = waitpid(-1, &status, 0);
        if (stopped == -1) break;

        if (WIFEXITED(status)) {
            log_info("PID %d exited with code %d.", stopped, WEXITSTATUS(status));
            remove_pid(stopped);
            if (watched_count == 0) break;
            continue;
        }
        if (WIFSIGNALED(status)) {
            log_info("PID %d killed by signal %d.", stopped, WTERMSIG(status));
            remove_pid(stopped);
            if (watched_count == 0) break;
            continue;
        }

        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            unsigned long new_pid = 0;
            ptrace(PTRACE_GETEVENTMSG, stopped, 0, &new_pid);
            log_info("New child process born: PID %lu — adding to watchlist", new_pid);
            add_pid((pid_t)new_pid);
            set_trace_options((pid_t)new_pid);
            fork_clone_total++;
            continue;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, stopped, 0, &regs) == -1) continue;

        check_syscall(stopped, &regs);

        ptrace(PTRACE_SYSCALL, stopped, 0, 0);
        waitpid(stopped, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_pid(stopped);
            if (watched_count == 0) break;
        }
    }

    log_info("IDS session complete. Total child processes spawned: %d", fork_clone_total);
    log_info("Full alert log saved to: ids_alerts.log");
    return 0;
}
EOF

# ── src/main.c ─────────────────────────────────────────────
cat > src/main.c << 'EOF'
#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "monitor.h"
#include "logger.h"

#define LOG_FILE "ids_alerts.log"

int main(int argc, char **argv) {
    if (argc <= 1) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        fprintf(stderr, "       sudo %s ls /etc\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (logger_init(LOG_FILE) != 0) {
        fprintf(stderr, "[IDS FATAL] Cannot open log file %s: %s\n",
                LOG_FILE, strerror(errno));
        return EXIT_FAILURE;
    }

    int ret = monitor_run(argc, argv);
    logger_close();
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
EOF

# ── tests/test_targets.c ───────────────────────────────────
cat > tests/test_targets.c << 'EOF'
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
EOF

# ── Makefile ───────────────────────────────────────────────
cat > Makefile << 'EOF'
CC     = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -Iinclude
TARGET = ids_monitor
TEST   = test_targets
SRCS   = src/main.c src/monitor.c src/syscall_filter.c src/logger.c
OBJS   = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET) $(TEST)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST): tests/test_targets.c
	$(CC) $(CFLAGS) -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: all
	@echo "Run: sudo ./$(TARGET) ./$(TEST) <1-6>"

clean:
	rm -f $(OBJS) $(TARGET) $(TEST) ids_alerts.log
EOF

# ── .gitignore ─────────────────────────────────────────────
cat > .gitignore << 'EOF'
ids_monitor
test_targets
src/*.o
ids_alerts.log
.vscode/
*.swp
*~
.DS_Store
EOF

# ── README.md ──────────────────────────────────────────────
cat > README.md << 'EOF'
# syscall-watchdog

A lightweight Linux **Intrusion Detection System (IDS)** built in C.

It uses `ptrace` to attach to a target process and monitor every syscall it makes
in real time — alerting on sensitive file access, fork bombs, privilege escalation,
shellcode injection patterns, and more.

## How it works

`syscall-watchdog` forks a child process, attaches via `ptrace`, and intercepts
every syscall entry. It also traces grandchildren automatically using
`PTRACE_O_TRACEFORK` and `PTRACE_O_TRACECLONE`, so no subprocess escapes monitoring.

Alerts are printed to stderr in red and written to `ids_alerts.log`.

## Detection rules

| Rule | Syscall(s) | Trigger |
|------|-----------|---------|
| Sensitive file access | `open`, `openat` | `/etc/shadow`, SSH keys, etc. |
| Suspicious shell spawn | `execve` | `bash -c`, `bash -i`, netcat |
| Fork bomb | `fork`, `clone` | More than 20 forks in one session |
| Internet socket | `socket` | `AF_INET` / `AF_INET6` (local sockets ignored) |
| Privilege escalation | `setuid`, `setgid` | Called with UID/GID 0 |
| Anti-debug / injection | `ptrace` | Any `ptrace` call from the tracee |
| Log tampering | `unlink` | Deleting files under `/var/log` or `/tmp` |
| Shellcode injection | `mprotect` | Mapping memory as `PROT_WRITE|PROT_EXEC` |

## Build

```bash
make
```

Requires GCC on Linux x86-64. No external dependencies.

## Usage

```bash
sudo ./ids_monitor <program> [args...]
sudo ./ids_monitor ls /etc
sudo ./ids_monitor ./test_targets 1
```

## Running the tests

```bash
make
sudo ./ids_monitor ./test_targets 1   # sensitive file access
sudo ./ids_monitor ./test_targets 2   # fork bomb
sudo ./ids_monitor ./test_targets 3   # internet socket
sudo ./ids_monitor ./test_targets 4   # privilege escalation
sudo ./ids_monitor ./test_targets 5   # shellcode pattern
sudo ./ids_monitor ./test_targets 6   # log tampering
```

## Project structure

```
syscall-watchdog/
├── include/
│   ├── logger.h
│   ├── monitor.h
│   └── syscall_filter.h
├── src/
│   ├── main.c
│   ├── monitor.c
│   ├── syscall_filter.c
│   └── logger.c
├── tests/
│   └── test_targets.c
├── Makefile
└── .gitignore
```

## Platform

Linux x86-64 only.
EOF

echo "[4/7] Building to verify..."
make

echo "[5/7] Staging files..."
git add include/ src/ tests/ Makefile .gitignore README.md

echo "[6/7] Committing in logical order..."
git add include/ src/main.c Makefile .gitignore
git commit -m "refactor: split into multi-file structure with headers"

git add src/logger.c include/logger.h
git commit -m "feat(logger): extract logging into its own module"

git add src/syscall_filter.c include/syscall_filter.h
git commit -m "feat(syscall_filter): extract detection rules into dedicated module"

git add src/monitor.c include/monitor.h
git commit -m "feat(monitor): extract ptrace loop and child tracking into monitor module"

git add tests/
git commit -m "test: move test_targets into tests/ directory"

git add README.md
git commit -m "docs: add README with usage, rules table, and project structure"

echo "[7/7] Pushing to GitHub..."
git push origin master

echo ""
echo "✅ Done! Your repo is now fully refactored and pushed."
echo "   Go add topics on GitHub: c linux security ptrace syscall ids intrusion-detection"

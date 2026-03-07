#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/ptrace.h>

#define LOG_FILE        "ids_alerts.log"
#define FORK_BOMB_LIMIT  20
#define MAX_PATH_LEN     256

#define FATAL(...) \
    do { \
        fprintf(stderr, "[IDS FATAL] " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

#define ALERT(...) \
    do { log_alert(__VA_ARGS__); } while(0)

static FILE *log_fp     = NULL;
static int   fork_count = 0;
static pid_t traced_pid = -1;  /* needed by the signal handler */

typedef struct {
    long  number;
    char *name;
} SyscallEntry;

static const SyscallEntry syscall_names[] = {
    { SYS_read,     "read"     },
    { SYS_write,    "write"    },
    { SYS_open,     "open"     },
    { SYS_openat,   "openat"   },
    { SYS_close,    "close"    },
    { SYS_execve,   "execve"   },
    { SYS_fork,     "fork"     },
    { SYS_clone,    "clone"    },
    { SYS_socket,   "socket"   },
    { SYS_connect,  "connect"  },
    { SYS_bind,     "bind"     },
    { SYS_listen,   "listen"   },
    { SYS_setuid,   "setuid"   },
    { SYS_setgid,   "setgid"   },
    { SYS_ptrace,   "ptrace"   },
    { SYS_kill,     "kill"     },
    { SYS_unlink,   "unlink"   },
    { SYS_chmod,    "chmod"    },
    { SYS_chown,    "chown"    },
    { SYS_mmap,     "mmap"     },
    { SYS_mprotect, "mprotect" },
    { -1,           "unknown"  }
};

static const char *sensitive_files[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
    "/root/.bash_history",
    "/.ssh/id_rsa",
    "/etc/crontab",
    "/var/log/auth.log",
    NULL
};

static void log_alert(const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(stderr, "\033[1;31m[ALERT %s]\033[0m ", timebuf);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");

    /* va_list is consumed after the first vfprintf, need a fresh one for the file */
    if (log_fp) {
        fprintf(log_fp, "[ALERT %s] ", timebuf);
        va_list args2;
        va_start(args2, fmt);
        vfprintf(log_fp, fmt, args2);
        va_end(args2);
        fprintf(log_fp, "\n");
        fflush(log_fp);  /* don't lose alerts if we crash */
    }
}

static void log_info(const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(stderr, "\033[0;36m[INFO  %s]\033[0m ", timebuf);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");

    if (log_fp) {
        fprintf(log_fp, "[INFO  %s] ", timebuf);
        va_list args2;
        va_start(args2, fmt);
        vfprintf(log_fp, fmt, args2);
        va_end(args2);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
}

__attribute__((unused))
static const char *get_syscall_name(long num) {
    for (int i = 0; syscall_names[i].number != -1; i++)
        if (syscall_names[i].number == num)
            return syscall_names[i].name;
    return "unknown";
}

/*
 * ptrace can only peek one word at a time, so we walk the string
 * 8 bytes at a time until we hit a null terminator.
 * ref: https://nullprogram.com/blog/2018/06/23/
 */
static void read_string_from_tracee(pid_t pid, long addr, char *buf, size_t size) {
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

static int is_sensitive_file(const char *path) {
    for (int i = 0; sensitive_files[i] != NULL; i++)
        if (strstr(path, sensitive_files[i]) != NULL)
            return 1;
    return 0;
}

static void check_syscall(pid_t pid, struct user_regs_struct *regs) {
    long syscall_num = regs->orig_rax;

    if (syscall_num == SYS_open || syscall_num == SYS_openat) {
        char path[MAX_PATH_LEN] = {0};
        /* openat(dirfd, path, ...) vs open(path, ...) — path is in different regs */
        long path_addr = (syscall_num == SYS_openat)
                         ? (long)regs->rsi
                         : (long)regs->rdi;
        read_string_from_tracee(pid, path_addr, path, sizeof(path));
        if (is_sensitive_file(path))
            ALERT("PID %d tried to open SENSITIVE file: %s", pid, path);
    }

    else if (syscall_num == SYS_execve) {
        char prog[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, prog, sizeof(prog));
        log_info("PID %d called execve(\"%s\")", pid, prog);
        /* attacker dropping a shell after exploiting something */
        if (strstr(prog, "nc")     ||
            strstr(prog, "bash")   ||
            strstr(prog, "sh")     ||
            strstr(prog, "python") ||
            strstr(prog, "perl"))
            ALERT("PID %d spawning suspicious shell/interpreter: %s", pid, prog);
    }

    else if (syscall_num == SYS_fork || syscall_num == SYS_clone) {
        fork_count++;
        if (fork_count > FORK_BOMB_LIMIT)
            ALERT("PID %d possible FORK BOMB detected! fork/clone called %d times",
                  pid, fork_count);
    }

    else if (syscall_num == SYS_socket) {
        int domain = (int)regs->rdi;
        int type   = (int)regs->rsi;
        log_info("PID %d created socket(domain=%d, type=%d)", pid, domain, type);
        ALERT("PID %d opened a NETWORK SOCKET — possible C2 or data exfiltration", pid);
    }

    else if (syscall_num == SYS_setuid) {
        int uid = (int)regs->rdi;
        if (uid == 0)
            ALERT("PID %d called setuid(0) — PRIVILEGE ESCALATION attempt!", pid);
    }

    else if (syscall_num == SYS_setgid) {
        int gid = (int)regs->rdi;
        if (gid == 0)
            ALERT("PID %d called setgid(0) — PRIVILEGE ESCALATION attempt!", pid);
    }

    else if (syscall_num == SYS_ptrace) {
        /*
         * legitimate processes don't call ptrace on themselves.
         * malware does this to detect if it's being traced — if PTRACE_TRACEME
         * returns EPERM, a debugger is already attached.
         */
        ALERT("PID %d called ptrace() — possible ANTI-DEBUG or process injection attempt!", pid);
    }

    else if (syscall_num == SYS_unlink) {
        char path[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, path, sizeof(path));
        /* covering tracks after an intrusion */
        if (strstr(path, "/var/log") || strstr(path, "/tmp"))
            ALERT("PID %d deleting suspicious file: %s", pid, path);
    }

    else if (syscall_num == SYS_mprotect) {
        int prot = (int)regs->rdx;
        /*
         * PROT_WRITE|PROT_EXEC on the same region means someone just wrote
         * shellcode into a buffer and is making it executable. normal
         * allocations are never both writable and executable at the same time.
         */
        if ((prot & 0x4) && (prot & 0x2))
            ALERT("PID %d called mprotect(PROT_WRITE|PROT_EXEC) — possible SHELLCODE injection!", pid);
    }
}

static void handle_sigint(int sig) {
    (void)sig;
    log_info("IDS shutting down (SIGINT received).");
    if (log_fp) fclose(log_fp);
    /* detach cleanly so the traced process isn't left frozen */
    if (traced_pid > 0)
        ptrace(PTRACE_DETACH, traced_pid, 0, 0);
    exit(0);
}

int main(int argc, char **argv) {
    if (argc <= 1)
        FATAL("Usage: %s <program> [args...]\n       sudo %s ls /etc", argv[0], argv[0]);

    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp)
        FATAL("Cannot open log file %s: %s", LOG_FILE, strerror(errno));

    signal(SIGINT, handle_sigint);

    log_info("IDS started. Monitoring: %s", argv[1]);
    fprintf(stderr, "\033[1;33m[IDS] Monitoring '%s' — alerts will appear in red\033[0m\n\n", argv[1]);

    pid_t pid = fork();
    switch (pid) {
        case -1:
            FATAL("%s", strerror(errno));
        case 0:
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execvp(argv[1], argv + 1);
            FATAL("execvp failed: %s", strerror(errno));
    }

    traced_pid = pid;
    waitpid(pid, 0, 0);  /* wait for the initial SIGSTOP from PTRACE_TRACEME */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
        /* run until next syscall entry */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            log_info("Monitored process (PID %d) exited with code %d.",
                     pid, WEXITSTATUS(status));
            break;
        }
        if (WIFSIGNALED(status)) {
            log_info("Monitored process (PID %d) killed by signal %d.",
                     pid, WTERMSIG(status));
            break;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            continue;

        check_syscall(pid, &regs);

        /* let the syscall actually execute, then catch the exit */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;
    }

    log_info("IDS session complete. Total fork/clone calls detected: %d", fork_count);
    log_info("Full alert log saved to: %s", LOG_FILE);

    if (log_fp) fclose(log_fp);
    return 0;
}         * (before kernel services the call  same as strace) */
        check_syscall(pid, &regs);

        /* step 2: let syscall actually execute, wait for syscall EXIT */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;
    }

    log_info("IDS session complete. Total fork/clone calls detected: %d", fork_count);
    log_info("Full alert log saved to: %s", LOG_FILE);

    if (log_fp) fclose(log_fp);
    return 0;
}

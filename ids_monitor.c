/*
 * ids_monitor.c - System Call Intrusion Detection System
 *
 * Based on skeeto/ptrace-examples (https://github.com/skeeto/ptrace-examples)
 * Extended with IDS rule engine, logging, and security alerting.
 *
 * OS Concepts: process management, signals, system calls, file I/O, IPC
 * Security Concepts: syscall monitoring, anomaly detection, privilege escalation detection
 *
 * Compile: gcc -O2 -Wall -std=c11 ids_monitor.c -o ids_monitor
 * Usage:   sudo ./ids_monitor <program> [args...]
 */

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

/* ─────────────────────────────────────────────
 *  CONFIG
 * ───────────────────────────────────────────── */
#define LOG_FILE        "ids_alerts.log"
#define FORK_BOMB_LIMIT  20       /* max allowed fork() calls before alert  */
#define MAX_PATH_LEN     256      /* max length we read for filename args    */

/* ─────────────────────────────────────────────
 *  MACROS
 * ───────────────────────────────────────────── */
#define FATAL(...) \
    do { \
        fprintf(stderr, "[IDS FATAL] " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

#define ALERT(...) \
    do { \
        log_alert(__VA_ARGS__); \
    } while(0)

/* ─────────────────────────────────────────────
 *  GLOBALS
 * ───────────────────────────────────────────── */
static FILE *log_fp  = NULL;
static int   fork_count = 0;    /* tracks how many times fork was called   */
static pid_t traced_pid = -1;   /* pid of the process we are monitoring    */

/* ─────────────────────────────────────────────
 *  SYSCALL NAME TABLE
 *  Only the ones we care about — keeps it readable
 * ───────────────────────────────────────────── */
typedef struct {
    long   number;
    char  *name;
} SyscallEntry;

/* Map syscall number -> human readable name */
static const SyscallEntry syscall_names[] = {
    { SYS_read,       "read"       },
    { SYS_write,      "write"      },
    { SYS_open,       "open"       },
    { SYS_openat,     "openat"     },
    { SYS_close,      "close"      },
    { SYS_execve,     "execve"     },
    { SYS_fork,       "fork"       },
    { SYS_clone,      "clone"      },
    { SYS_socket,     "socket"     },
    { SYS_connect,    "connect"    },
    { SYS_bind,       "bind"       },
    { SYS_listen,     "listen"     },
    { SYS_setuid,     "setuid"     },
    { SYS_setgid,     "setgid"     },
    { SYS_ptrace,     "ptrace"     },
    { SYS_kill,       "kill"       },
    { SYS_unlink,     "unlink"     },
    { SYS_chmod,      "chmod"      },
    { SYS_chown,      "chown"      },
    { SYS_mmap,       "mmap"       },
    { SYS_mprotect,   "mprotect"   },
    { -1,             "unknown"    }   /* sentinel */
};

/* ─────────────────────────────────────────────
 *  SENSITIVE FILE PATHS — trigger alert on access
 * ───────────────────────────────────────────── */
static const char *sensitive_files[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
    "/root/.bash_history",
    "/.ssh/id_rsa",
    "/etc/crontab",
    "/var/log/auth.log",
    NULL   /* sentinel */
};

/* ─────────────────────────────────────────────
 *  LOGGING
 * ───────────────────────────────────────────── */
static void log_alert(const char *fmt, ...) {
    /* get current timestamp */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    /* print to stderr so user sees it live */
    fprintf(stderr, "\033[1;31m[ALERT %s]\033[0m ", timebuf);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");

    /* also write to log file */
    if (log_fp) {
        fprintf(log_fp, "[ALERT %s] ", timebuf);
        va_list args2;
        va_start(args2, fmt);
        vfprintf(log_fp, fmt, args2);
        va_end(args2);
        fprintf(log_fp, "\n");
        fflush(log_fp);
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

/* ─────────────────────────────────────────────
 *  HELPERS
 * ───────────────────────────────────────────── */

/* get syscall name from number — used for verbose logging extensions */
__attribute__((unused))
static const char *get_syscall_name(long syscall_num) {
    for (int i = 0; syscall_names[i].number != -1; i++) {
        if (syscall_names[i].number == syscall_num)
            return syscall_names[i].name;
    }
    return "unknown";
}

/*
 * Read a string from the tracee's memory using PTRACE_PEEKDATA.
 * addr  = address of the string in tracee's address space
 * buf   = output buffer
 * size  = max bytes to read
 *
 * This is how we read filename arguments from openat(), execve() etc.
 * Technique taken from: https://nullprogram.com/blog/2018/06/23/
 */
static void read_string_from_tracee(pid_t pid, long addr, char *buf, size_t size) {
    size_t i = 0;
    while (i < size - 1) {
        /* PTRACE_PEEKDATA reads one word (8 bytes on x86_64) at a time */
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), 0);
        if (word == -1) break;

        /* copy byte by byte and stop at null terminator */
        char *bytes = (char *)&word;
        for (int b = 0; b < 8 && i < size - 1; b++, i++) {
            buf[i] = bytes[b];
            if (bytes[b] == '\0') goto done;
        }
    }
done:
    buf[i] = '\0';
}

/* check if the path matches any of our sensitive file list */
static int is_sensitive_file(const char *path) {
    for (int i = 0; sensitive_files[i] != NULL; i++) {
        if (strstr(path, sensitive_files[i]) != NULL)
            return 1;
    }
    return 0;
}

/* ─────────────────────────────────────────────
 *  IDS RULE ENGINE
 *  Called on every syscall entry — this is where
 *  the detection logic lives.
 * ───────────────────────────────────────────── */
static void check_syscall(pid_t pid, struct user_regs_struct *regs) {
    long syscall_num = regs->orig_rax;

    /* ── RULE 1: Sensitive file access ─────────── */
    if (syscall_num == SYS_open || syscall_num == SYS_openat) {
        char path[MAX_PATH_LEN] = {0};

        /* openat(dirfd, pathname, flags) → pathname is rsi
         * open(pathname, flags)          → pathname is rdi  */
        long path_addr = (syscall_num == SYS_openat)
                         ? (long)regs->rsi
                         : (long)regs->rdi;

        read_string_from_tracee(pid, path_addr, path, sizeof(path));

        if (is_sensitive_file(path)) {
            ALERT("PID %d tried to open SENSITIVE file: %s", pid, path);
        }
    }

    /* ── RULE 2: execve — new process execution ─ */
    else if (syscall_num == SYS_execve) {
        char prog[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, prog, sizeof(prog));
        log_info("PID %d called execve(\"%s\")", pid, prog);

        /* flag suspicious binaries */
        if (strstr(prog, "nc")     != NULL ||
            strstr(prog, "bash")   != NULL ||
            strstr(prog, "sh")     != NULL ||
            strstr(prog, "python") != NULL ||
            strstr(prog, "perl")   != NULL) {
            ALERT("PID %d spawning suspicious shell/interpreter: %s", pid, prog);
        }
    }

    /* ── RULE 3: Fork bomb detection ────────────── */
    else if (syscall_num == SYS_fork || syscall_num == SYS_clone) {
        fork_count++;
        if (fork_count > FORK_BOMB_LIMIT) {
            ALERT("PID %d possible FORK BOMB detected! fork/clone called %d times",
                  pid, fork_count);
        }
    }

    /* ── RULE 4: Network socket creation ────────── */
    else if (syscall_num == SYS_socket) {
        int domain   = (int)regs->rdi;
        int type     = (int)regs->rsi;
        log_info("PID %d created socket(domain=%d, type=%d)", pid, domain, type);
        ALERT("PID %d opened a NETWORK SOCKET — possible C2 or data exfiltration", pid);
    }

    /* ── RULE 5: Privilege escalation ───────────── */
    else if (syscall_num == SYS_setuid) {
        int uid = (int)regs->rdi;
        if (uid == 0) {
            ALERT("PID %d called setuid(0) — PRIVILEGE ESCALATION attempt!", pid);
        }
    }

    else if (syscall_num == SYS_setgid) {
        int gid = (int)regs->rdi;
        if (gid == 0) {
            ALERT("PID %d called setgid(0) — PRIVILEGE ESCALATION attempt!", pid);
        }
    }

    /* ── RULE 6: Anti-debug detection ───────────── */
    /* If the traced program itself calls ptrace(), it may be
     * trying to detect that it IS being traced (common malware trick) */
    else if (syscall_num == SYS_ptrace) {
        ALERT("PID %d called ptrace() — possible ANTI-DEBUG or process injection attempt!", pid);
    }

    /* ── RULE 7: File deletion ───────────────────── */
    else if (syscall_num == SYS_unlink) {
        char path[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, path, sizeof(path));

        /* alert if deleting logs — classic attacker cleanup */
        if (strstr(path, "/var/log") || strstr(path, "/tmp")) {
            ALERT("PID %d deleting suspicious file: %s", pid, path);
        }
    }

    /* ── RULE 8: mprotect with EXEC — shellcode? ── */
    else if (syscall_num == SYS_mprotect) {
        int prot = (int)regs->rdx;
        /* PROT_EXEC = 0x4, PROT_WRITE = 0x2 */
        if ((prot & 0x4) && (prot & 0x2)) {
            ALERT("PID %d called mprotect(PROT_WRITE|PROT_EXEC) — possible SHELLCODE injection!", pid);
        }
    }
}

/* ─────────────────────────────────────────────
 *  SIGNAL HANDLER — clean exit on Ctrl+C
 * ───────────────────────────────────────────── */
static void handle_sigint(int sig) {
    (void)sig;
    log_info("IDS shutting down (SIGINT received).");
    if (log_fp) fclose(log_fp);

    /* detach from traced process and let it continue */
    if (traced_pid > 0)
        ptrace(PTRACE_DETACH, traced_pid, 0, 0);

    exit(0);
}

/* ─────────────────────────────────────────────
 *  MAIN
 * ───────────────────────────────────────────── */
int main(int argc, char **argv) {
    if (argc <= 1)
        FATAL("Usage: %s <program> [args...]\n       sudo %s ls /etc", argv[0], argv[0]);

    /* open log file */
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp)
        FATAL("Cannot open log file %s: %s", LOG_FILE, strerror(errno));

    /* set up Ctrl+C handler */
    signal(SIGINT, handle_sigint);

    log_info("IDS started. Monitoring: %s", argv[1]);
    fprintf(stderr, "\033[1;33m[IDS] Monitoring '%s' — alerts will appear in red\033[0m\n\n", argv[1]);

    /* ── FORK: same pattern as skeeto/ptrace-examples ── */
    pid_t pid = fork();
    switch (pid) {
        case -1:
            FATAL("%s", strerror(errno));

        case 0: /* child — becomes the traced process */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* execvp blocks here until parent attaches and resumes us */
            execvp(argv[1], argv + 1);
            FATAL("execvp failed: %s", strerror(errno));
    }

    /* parent — this is the IDS tracer */
    traced_pid = pid;

    /* wait for child's initial SIGSTOP from PTRACE_TRACEME */
    waitpid(pid, 0, 0);

    /* kill child when tracer exits — so we never leave an unmonitored process */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    /* ── MAIN MONITORING LOOP ── */
    for (;;) {
        /* step 1: run child until next syscall ENTRY */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        int status;
        waitpid(pid, &status, 0);

        /* if child exited, we are done */
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

        /* read registers — syscall number and arguments are in here */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            continue;

        /* run our IDS rule engine on syscall ENTRY
         * (before kernel services the call — same as strace) */
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

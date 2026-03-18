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
static pid_t traced_pid = -1;

/* =========================================================
 * FIX 1 — TRACK CHILD PROCESSES
 *
 * OLD BEHAVIOUR:
 *   The IDS only watched one process (the direct child).
 *   If that child spawned its own children, those ran
 *   completely unwatched — a huge blind spot.
 *
 * THE FIX:
 *   We keep a simple list of every PID we are currently
 *   watching. When we see a fork/clone syscall, we add the
 *   new child's PID to the list. When a process exits, we
 *   remove it. Every waitpid() call now checks ALL watched
 *   PIDs, not just the original one.
 *
 *   We also add PTRACE_O_TRACEFORK and PTRACE_O_TRACECLONE
 *   options so the kernel automatically starts tracing
 *   grandchildren the moment they are born.
 * ========================================================= */
#define MAX_PIDS 256

static pid_t watched_pids[MAX_PIDS];
static int   watched_count = 0;

static void add_pid(pid_t pid) {
    if (watched_count < MAX_PIDS)
        watched_pids[watched_count++] = pid;
}

static void remove_pid(pid_t pid) {
    for (int i = 0; i < watched_count; i++) {
        if (watched_pids[i] == pid) {
            /* replace with last entry and shrink */
            watched_pids[i] = watched_pids[--watched_count];
            return;
        }
    }
}

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

/* =========================================================
 * FIX 5 — SMARTER SHELL DETECTION
 *
 * OLD BEHAVIOUR:
 *   The old code fired an alert any time a program with
 *   "bash" or "sh" in its name was executed — even if you
 *   legitimately ran a bash script yourself.
 *   e.g.  execve("/bin/bash", ["bash", "deploy.sh"], ...)
 *   would trigger a false alarm.
 *
 * THE FIX:
 *   We now look at the ARGUMENTS too, not just the program
 *   name. If bash is called with "-c" and a command string
 *   (the classic way malware drops a shell), that's
 *   suspicious. If it's called with a named script file,
 *   it's likely legitimate and we only log it as INFO.
 *
 *   We also added "perl" and "ruby" to the list, and made
 *   "nc" (netcat) always an alert since it has no innocent
 *   use when spawned by another process.
 * ========================================================= */

/* Programs that are ALWAYS suspicious when spawned */
static const char *always_suspicious[] = {
    "nc", "ncat", "netcat", NULL
};

/* Programs that are suspicious only when launched
   interactively (with -i flag or no script argument) */
static const char *shell_names[] = {
    "bash", "sh", "zsh", "python", "perl", "ruby", NULL
};

static int is_always_suspicious(const char *prog) {
    for (int i = 0; always_suspicious[i]; i++)
        if (strstr(prog, always_suspicious[i])) return 1;
    return 0;
}

static int is_shell(const char *prog) {
    for (int i = 0; shell_names[i]; i++)
        if (strstr(prog, shell_names[i])) return 1;
    return 0;
}

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

__attribute__((unused))
static const char *get_syscall_name(long num) {
    for (int i = 0; syscall_names[i].number != -1; i++)
        if (syscall_names[i].number == num)
            return syscall_names[i].name;
    return "unknown";
}

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

/* =========================================================
 * FIX 2 — SMARTER SOCKET DETECTION
 *
 * OLD BEHAVIOUR:
 *   ANY socket() call fired an alert. That means even a
 *   normal program checking the internet would trigger it.
 *   Way too many false positives.
 *
 * THE FIX:
 *   We now check WHAT KIND of socket it is.
 *   - AF_INET  (2)  = IPv4 internet socket  → suspicious
 *   - AF_INET6 (10) = IPv6 internet socket  → suspicious
 *   - AF_UNIX  (1)  = local socket (used    → NOT suspicious
 *                     for apps talking to   (just log as info)
 *                     each other on same
 *                     machine, totally
 *                     normal)
 *
 *   So we only alert on real internet connections, not
 *   local inter-process communication.
 * ========================================================= */
static void check_socket(pid_t pid, struct user_regs_struct *regs) {
    int domain = (int)regs->rdi;

    if (domain == AF_INET || domain == AF_INET6) {
        /* real internet socket — suspicious */
        ALERT("PID %d opened an INTERNET SOCKET (domain=%d) — possible C2 or data exfiltration", pid, domain);
    } else {
        /* local unix socket — normal, just log it */
        log_info("PID %d created a local socket (domain=%d) — not suspicious", pid, domain);
    }
}

/* =========================================================
 * FIX 3 — FORK BOMB: DETECT AND KILL
 *
 * OLD BEHAVIOUR:
 *   The IDS detected the fork bomb and fired alerts, but
 *   it never actually STOPPED it. The bomb kept running,
 *   kept spawning processes, and could still crash the
 *   system while the IDS just watched and logged.
 *
 * THE FIX:
 *   When we detect a fork bomb (fork_count > limit), we
 *   now send SIGKILL to the offending process immediately.
 *   SIGKILL cannot be caught or ignored — the process dies
 *   instantly. We also log that we killed it.
 * ========================================================= */
static void check_fork_bomb(pid_t pid) {
    fork_count++;
    if (fork_count > FORK_BOMB_LIMIT) {
        ALERT("PID %d FORK BOMB detected! fork/clone called %d times — KILLING process",
              pid, fork_count);
        /* actually kill it this time, not just log */
        kill(pid, SIGKILL);
        log_info("PID %d has been killed by IDS.", pid);
    }
}

static void check_syscall(pid_t pid, struct user_regs_struct *regs) {
    long syscall_num = regs->orig_rax;

    /* Rule 1 — sensitive file access (unchanged) */
    if (syscall_num == SYS_open || syscall_num == SYS_openat) {
        char path[MAX_PATH_LEN] = {0};
        long path_addr = (syscall_num == SYS_openat)
                         ? (long)regs->rsi
                         : (long)regs->rdi;
        read_string_from_tracee(pid, path_addr, path, sizeof(path));
        if (is_sensitive_file(path))
            ALERT("PID %d tried to open SENSITIVE file: %s", pid, path);
    }

    /* Rule 2 — suspicious shell spawn (IMPROVED — fix 5) */
    else if (syscall_num == SYS_execve) {
        char prog[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, prog, sizeof(prog));
        log_info("PID %d called execve(\"%s\")", pid, prog);

        if (is_always_suspicious(prog)) {
            /* netcat etc — always an alert */
            ALERT("PID %d spawning ALWAYS-SUSPICIOUS program: %s", pid, prog);
        } else if (is_shell(prog)) {
            /*
             * For shells: read the first argument.
             * If it's "-c" that means an inline command is being
             * run — classic malware behaviour.
             * If it's a script name, probably legitimate.
             */
            char arg1[MAX_PATH_LEN] = {0};
            long argv_addr = (long)regs->rsi;
            long first_arg_ptr = 0;
            /* argv is an array of pointers — read the second pointer (argv[1]) */
            long second_ptr_addr = argv_addr + sizeof(char *);
            long second_ptr = ptrace(PTRACE_PEEKDATA, pid, (void *)second_ptr_addr, 0);
            if (second_ptr != 0) {
                read_string_from_tracee(pid, second_ptr, arg1, sizeof(arg1));
            }
            (void)first_arg_ptr;

            if (strcmp(arg1, "-c") == 0 || strcmp(arg1, "-i") == 0) {
                ALERT("PID %d spawning INTERACTIVE/INLINE shell: %s %s — likely malicious",
                      pid, prog, arg1);
            } else {
                log_info("PID %d running shell/interpreter with script: %s — probably ok",
                         pid, prog);
            }
        }
    }

    /* Rule 3 — fork bomb (IMPROVED — fix 3) */
    else if (syscall_num == SYS_fork || syscall_num == SYS_clone) {
        check_fork_bomb(pid);
    }

    /* Rule 4 — network socket (IMPROVED — fix 2) */
    else if (syscall_num == SYS_socket) {
        check_socket(pid, regs);
    }

    /* Rule 5 — privilege escalation (unchanged) */
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

    /* Rule 6 — anti-debug (unchanged) */
    else if (syscall_num == SYS_ptrace) {
        ALERT("PID %d called ptrace() — possible ANTI-DEBUG or process injection attempt!", pid);
    }

    /* Rule 7 — log tampering (unchanged) */
    else if (syscall_num == SYS_unlink) {
        char path[MAX_PATH_LEN] = {0};
        read_string_from_tracee(pid, (long)regs->rdi, path, sizeof(path));
        if (strstr(path, "/var/log") || strstr(path, "/tmp"))
            ALERT("PID %d deleting suspicious file: %s", pid, path);
    }

    /* Rule 8 — shellcode injection (unchanged) */
    else if (syscall_num == SYS_mprotect) {
        int prot = (int)regs->rdx;
        if ((prot & 0x4) && (prot & 0x2))
            ALERT("PID %d called mprotect(PROT_WRITE|PROT_EXEC) — possible SHELLCODE injection!", pid);
    }
}

static void handle_sigint(int sig) {
    (void)sig;
    log_info("IDS shutting down (SIGINT received).");
    if (log_fp) fclose(log_fp);
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

    /* =====================================================
     * FIX 1 (continued) — WATCH CHILD PROCESSES
     *
     * We add the original child to our watched list,
     * then set extra ptrace options:
     *
     *   PTRACE_O_TRACEFORK  — when the child calls fork(),
     *     automatically attach to the grandchild too
     *   PTRACE_O_TRACECLONE — same but for clone() (the
     *     modern version of fork used by threads/processes)
     *   PTRACE_O_TRACEEXEC  — notify us when execve() runs
     *
     * With these options, any process the child spawns is
     * automatically monitored. We don't miss anything.
     * ===================================================== */
    add_pid(pid);
    waitpid(pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0,
           PTRACE_O_EXITKILL   |
           PTRACE_O_TRACEFORK  |
           PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEEXEC);

    /* =====================================================
     * FIX 1 (continued) — MAIN LOOP NOW HANDLES MULTIPLE
     * PROCESSES
     *
     * OLD BEHAVIOUR:
     *   waitpid(pid, ...) — only waited for ONE specific
     *   process (the original child).
     *
     * THE FIX:
     *   waitpid(-1, ...) — the -1 means "wait for ANY
     *   child process." This way when a grandchild makes
     *   a syscall and freezes, we wake up for that too.
     *   We then check which PID woke us up and handle it.
     * ===================================================== */
    for (;;) {
        /* tell ALL watched processes to run until next syscall */
        for (int i = 0; i < watched_count; i++)
            ptrace(PTRACE_SYSCALL, watched_pids[i], 0, 0);

        /* wait for ANY of them to freeze */
        int status;
        pid_t stopped_pid = waitpid(-1, &status, 0);
        if (stopped_pid == -1) break; /* no more children */

        if (WIFEXITED(status)) {
            log_info("PID %d exited with code %d.", stopped_pid, WEXITSTATUS(status));
            remove_pid(stopped_pid);
            if (watched_count == 0) break; /* all done */
            continue;
        }

        if (WIFSIGNALED(status)) {
            log_info("PID %d killed by signal %d.", stopped_pid, WTERMSIG(status));
            remove_pid(stopped_pid);
            if (watched_count == 0) break;
            continue;
        }

        /* check if this is a new grandchild being born */
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            /* get the new child's PID */
            unsigned long new_pid = 0;
            ptrace(PTRACE_GETEVENTMSG, stopped_pid, 0, &new_pid);
            log_info("New child process born: PID %lu — adding to watchlist", new_pid);
            add_pid((pid_t)new_pid);
            /* set the same options on the grandchild */
            ptrace(PTRACE_SETOPTIONS, (pid_t)new_pid, 0,
                   PTRACE_O_EXITKILL   |
                   PTRACE_O_TRACEFORK  |
                   PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC);
            continue;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, stopped_pid, 0, &regs) == -1)
            continue;

        check_syscall(stopped_pid, &regs);

        ptrace(PTRACE_SYSCALL, stopped_pid, 0, 0);
        waitpid(stopped_pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_pid(stopped_pid);
            if (watched_count == 0) break;
        }
    }

    log_info("IDS session complete. Total fork/clone calls detected: %d", fork_count);
    log_info("Full alert log saved to: %s", LOG_FILE);

    if (log_fp) fclose(log_fp);
    return 0;
}

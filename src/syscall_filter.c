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

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

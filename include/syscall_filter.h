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

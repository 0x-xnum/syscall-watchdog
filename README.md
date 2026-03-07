# syscall-watchdog

A Linux Host-Based Intrusion Detection System (HIDS) built on `ptrace(2)`. Monitors every system call a process makes in real time and fires alerts when suspicious behaviour is detected — sensitive file access, privilege escalation, shellcode injection patterns, fork bombs, and more.

> Built as an OS project. Same core mechanism used by `strace`, `gdb`, and commercial EDR tools like CrowdStrike.

---

## How It Works

```
ids_monitor forks a child process
    └── child calls ptrace(PTRACE_TRACEME) → tells kernel: trace me
    └── child calls execvp(target_program) → becomes the monitored program

parent (IDS tracer) loop:
    ptrace(PTRACE_SYSCALL)   →  run child until next syscall entry
    waitpid()                ←  child paused, syscall not yet executed
    ptrace(PTRACE_GETREGS)      read CPU registers (orig_rax = syscall number, rdi/rsi/rdx = args)
    check_syscall()             run detection rules
    ptrace(PTRACE_SYSCALL)   →  let syscall execute
    waitpid()                ←  child paused at syscall exit
    [repeat until child exits]
```

Every syscall the monitored program makes passes through this loop. The IDS sees the syscall number and all arguments **before** the kernel services the call.

---

## Detection Rules

| # | Rule | Syscall(s) Monitored | Trigger |
|---|------|----------------------|---------|
| 1 | Sensitive file access | `open`, `openat` | Opens `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh`, etc. |
| 2 | Suspicious shell spawn | `execve` | Executes `bash`, `sh`, `nc`, `python`, `perl` |
| 3 | Fork bomb | `fork`, `clone` | More than 20 fork/clone calls total |
| 4 | Network socket | `socket` | Any socket creation |
| 5 | Privilege escalation | `setuid`, `setgid` | Called with uid/gid = 0 (root) |
| 6 | Anti-debug detection | `ptrace` | Monitored process calls ptrace itself |
| 7 | Log tampering | `unlink` | Deletes files in `/var/log` or `/tmp` |
| 8 | Shellcode injection | `mprotect` | Sets `PROT_WRITE \| PROT_EXEC` simultaneously |

---

## Build

**Requirements:** Linux x86-64, gcc, make

```bash
git clone https://github.com/0x-xnum/syscall-watchdog.git
cd syscall-watchdog
make
```

---

## Usage

```bash
# Monitor any program
sudo ./ids_monitor <program> [args...]

# Examples
sudo ./ids_monitor cat /etc/shadow
sudo ./ids_monitor wget https://example.com
sudo ./ids_monitor python3 -c "import socket; socket.socket()"
sudo ./ids_monitor ./test_targets 1
```

Alerts print to the terminal in **red** in real time. All events are also saved to `ids_alerts.log`.

---

## Test Cases

`test_targets` is a test harness that simulates six attack categories:

```bash
# 1 — sensitive file access (/etc/passwd, /etc/shadow)
sudo ./ids_monitor ./test_targets 1

# 2 — fork bomb (25 forks)
sudo ./ids_monitor ./test_targets 2

# 3 — network socket creation
sudo ./ids_monitor ./test_targets 3

# 4 — privilege escalation: setuid(0)
sudo ./ids_monitor ./test_targets 4

# 5 — shellcode pattern: mprotect(WRITE|EXEC)
sudo ./ids_monitor ./test_targets 5

# 6 — log tampering: unlink /tmp file
sudo ./ids_monitor ./test_targets 6
```

---

## Sample Output

```
[IDS] Monitoring 'cat' — alerts will appear in red

[ALERT 2026-03-07 14:24:47] PID 4181966 tried to open SENSITIVE file: /etc/shadow
[INFO  2026-03-07 14:24:47] IDS session complete.
[INFO  2026-03-07 14:24:47] Full alert log saved to: ids_alerts.log
```

```
[IDS] Monitoring './test_targets' — alerts will appear in red

[ALERT 2026-03-07 14:02:58] PID 4177664 possible FORK BOMB detected! fork/clone called 21 times
[ALERT 2026-03-07 14:02:58] PID 4177664 possible FORK BOMB detected! fork/clone called 22 times
[INFO  2026-03-07 14:02:58] Monitored process (PID 4177664) exited with code 0.
[INFO  2026-03-07 14:02:58] IDS session complete. Total fork/clone calls detected: 26
```

---

## OS Concepts

| Concept | Implementation |
|---------|---------------|
| Process creation | `fork()` creates the tracer/tracee pair |
| Process execution | `execvp()` replaces child with monitored program |
| Process synchronisation | `waitpid()` synchronises parent and child at every syscall |
| IPC | `ptrace()` is the communication channel between tracer and tracee |
| Signal handling | `SIGINT` handler for clean shutdown + `PTRACE_DETACH` |
| File I/O | Timestamped alert logging with `fopen`/`fprintf`/`fflush` |
| Virtual memory | `PTRACE_PEEKDATA` reads strings from tracee's address space |
| CPU architecture | x86-64 register convention — `orig_rax`, `rdi`, `rsi`, `rdx` |

---

## References

- [skeeto/ptrace-examples](https://github.com/skeeto/ptrace-examples) — base ptrace loop reference
- [Intercepting Linux Syscalls with Ptrace](https://nullprogram.com/blog/2018/06/23/) — nullprogram
- [ptrace(2) man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)

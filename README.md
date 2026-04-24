# syscall-watchdog

A lightweight Linux **Intrusion Detection System (IDS)** built in C.

It uses `ptrace` to attach to a target process and monitor every syscall it makes in real time — alerting on suspicious behaviour like sensitive file access, fork bombs, privilege escalation, shellcode injection patterns, and more.

---

## How it works

`syscall-watchdog` forks a child process, attaches via `ptrace`, and intercepts every syscall entry. It also traces grandchildren automatically using `PTRACE_O_TRACEFORK` and `PTRACE_O_TRACECLONE`, so no subprocess escapes monitoring.

Alerts are printed to `stderr` in red and written to `ids_alerts.log`.

---

## Detection rules

| Rule | Syscall(s) | What triggers it |
|------|-----------|-----------------|
| Sensitive file access | `open`, `openat` | Opening `/etc/shadow`, `/etc/passwd`, SSH keys, etc. |
| Suspicious shell spawn | `execve` | `bash -c`, `bash -i`, netcat, etc. |
| Fork bomb | `fork`, `clone` | More than 20 forks in one session |
| Internet socket | `socket` | `AF_INET` / `AF_INET6` sockets (local sockets ignored) |
| Privilege escalation | `setuid`, `setgid` | Calling with UID/GID 0 |
| Anti-debug / injection | `ptrace` | Any `ptrace` call from the tracee |
| Log tampering | `unlink` | Deleting files under `/var/log` or `/tmp` |
| Shellcode injection | `mprotect` | Mapping memory as `PROT_WRITE | PROT_EXEC` |

---

## Build

```bash
make
```

Requires GCC and a Linux system (x86-64). No external dependencies.

---

## Usage

```bash
sudo ./ids_monitor <program> [args...]
```

**Examples:**

```bash
sudo ./ids_monitor ls /etc
sudo ./ids_monitor ./test_targets 1
```

> `sudo` is required because `ptrace` needs elevated privileges to attach to processes.

---

## Running the tests

The `test_targets` binary is included to trigger each detection rule:

```bash
make
sudo ./ids_monitor ./test_targets 1   # sensitive file access
sudo ./ids_monitor ./test_targets 2   # fork bomb simulation
sudo ./ids_monitor ./test_targets 3   # internet socket
sudo ./ids_monitor ./test_targets 4   # privilege escalation
sudo ./ids_monitor ./test_targets 5   # shellcode pattern (mprotect RWX)
sudo ./ids_monitor ./test_targets 6   # log tampering (unlink /tmp)
```

---

## Project structure

```
syscall-watchdog/
├── include/
│   ├── logger.h          # logging interface
│   ├── monitor.h         # ptrace monitor loop
│   └── syscall_filter.h  # detection rules
├── src/
│   ├── main.c            # entry point
│   ├── monitor.c         # ptrace loop + child tracking
│   ├── syscall_filter.c  # all detection logic
│   └── logger.c          # timestamped alert/info logging
├── tests/
│   └── test_targets.c    # test programs (1 per rule)
├── Makefile
└── .gitignore
```

---

## Platform

Linux x86-64 only. The monitor reads `user_regs_struct` directly, which is architecture-specific.

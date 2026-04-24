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

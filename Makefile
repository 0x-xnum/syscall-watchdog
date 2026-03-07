# IDS Monitor - Makefile
# Compile: make
# Clean:   make clean

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
TARGETS = ids_monitor test_targets

all: $(TARGETS)

ids_monitor: ids_monitor.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built ids_monitor"

test_targets: test_targets.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built test_targets"

clean:
	rm -f $(TARGETS) ids_alerts.log

# ── How to run ──────────────────────────────────────────────────────────────
# Run a test:        sudo ./ids_monitor ./test_targets 1
# Monitor ls:        sudo ./ids_monitor ls /etc
# Monitor any prog:  sudo ./ids_monitor <program> [args]
# See alerts live:   watch the red [ALERT] lines in terminal
# See log file:      cat ids_alerts.log
# ─────────────────────────────────────────────────────────────────────────────

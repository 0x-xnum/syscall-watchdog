CC     = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -Iinclude
TARGET = ids_monitor
TEST   = test_targets
SRCS   = src/main.c src/monitor.c src/syscall_filter.c src/logger.c
OBJS   = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET) $(TEST)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST): tests/test_targets.c
	$(CC) $(CFLAGS) -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: all
	@echo "Run: sudo ./$(TARGET) ./$(TEST) <1-6>"

clean:
	rm -f $(OBJS) $(TARGET) $(TEST) ids_alerts.log

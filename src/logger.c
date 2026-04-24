#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "logger.h"

static FILE *log_fp = NULL;

int logger_init(const char *path) {
    log_fp = fopen(path, "a");
    return log_fp ? 0 : -1;
}

void logger_close(void) {
    if (log_fp) { fclose(log_fp); log_fp = NULL; }
}

static void write_log(const char *level, const char *color,
                      const char *fmt, va_list args) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(stderr, "%s[%-5s %s]\033[0m ", color, level, timebuf);
    va_list args_copy;
    va_copy(args_copy, args);
    vfprintf(stderr, fmt, args_copy);
    va_end(args_copy);
    fprintf(stderr, "\n");

    if (log_fp) {
        fprintf(log_fp, "[%-5s %s] ", level, timebuf);
        vfprintf(log_fp, fmt, args);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
}

void log_alert(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log("ALERT", "\033[1;31m", fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log("INFO", "\033[0;36m", fmt, args);
    va_end(args);
}

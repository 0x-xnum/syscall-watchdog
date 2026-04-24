#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "monitor.h"
#include "logger.h"

#define LOG_FILE "ids_alerts.log"

int main(int argc, char **argv) {
    if (argc <= 1) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        fprintf(stderr, "       sudo %s ls /etc\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (logger_init(LOG_FILE) != 0) {
        fprintf(stderr, "[IDS FATAL] Cannot open log file %s: %s\n",
                LOG_FILE, strerror(errno));
        return EXIT_FAILURE;
    }

    int ret = monitor_run(argc, argv);
    logger_close();
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

int  logger_init(const char *path);
void logger_close(void);
void log_alert(const char *fmt, ...);
void log_info(const char *fmt, ...);

#endif /* LOGGER_H */

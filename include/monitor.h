#ifndef MONITOR_H
#define MONITOR_H

#include <sys/types.h>

#define MAX_PIDS 256

extern pid_t watched_pids[MAX_PIDS];
extern int   watched_count;

void add_pid(pid_t pid);
void remove_pid(pid_t pid);
int  monitor_run(int argc, char **argv);

#endif /* MONITOR_H */

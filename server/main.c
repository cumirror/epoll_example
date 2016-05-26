#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>

#include "event.h"

extern int init_path();
extern int init_message();
extern int init_coding();

void ignore_signals(void)
{
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
}

void init_daemon()
{
    pid_t pid;
    int i, no_file;

    /*ignore some signals*/
    ignore_signals();

    pid = fork();
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    } else if (pid < 0) {
        perror("init_daemon: fork failed");
        exit(EXIT_FAILURE);
    }

    if (setsid() < 0) {
        perror("init_daemon: setsid failed");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    } else if (pid < 0) {
        perror("init_daemon: fork(2) failed");
        exit(EXIT_FAILURE);
    }

    /* close files opened by process */
    no_file = getdtablesize();
    for (i = 0; i < no_file; i++) {
        close(i);
    }

    openlog("newNac", LOG_CONS | LOG_PID, LOG_DAEMON);
}

void run_poll_loop() {
    syslog(LOG_INFO, "newNac start!");

    while (1) {
        Event.process_events();
    }
}

int main(int argc, char** argv) {
    char* path = NULL;

    if (argc == 2) {
        path = argv[1];
    }

    // help
    init_daemon();
    init_event();
    init_coding();
    init_connection();
    init_path(path);
    init_message();
    run_poll_loop();

    return 0;
}

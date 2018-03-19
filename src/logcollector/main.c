/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Logcollector daemon
 * Monitor some files and forward the output to our analysis system
 */

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "os_regex/os_regex.h"
#include "logcollector.h"

/* Prototypes */
static void help_logcollector(void) __attribute__((noreturn));

int debug_level;

/* Print help statement */
static void help_logcollector()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c;
    debug_level = 0;
    int test_config = 0, run_foreground = 0;
    const char *cfg = DEFAULTCPATH;
    gid_t gid;
    const char *group = GROUPGLOBAL;

    /* Setup random */
    srandom_init();

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vtdhfc:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_logcollector();
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_logcollector();
                break;
        }

    }

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("logcollector", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    /* Init message queue */
    w_msg_hash_queues_init();

    /* Read config file */
    if (LogCollectorConfig(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    /* Exit if test config */
    if (test_config) {
        exit(0);
    }

    /* No file available to monitor -- continue */
    if (logff == NULL) {
        os_calloc(2, sizeof(logreader), logff);
        logff[0].file = NULL;
        logff[0].ffile = NULL;
        logff[0].logformat = NULL;
        logff[0].fp = NULL;
        logff[1].file = NULL;
        logff[1].logformat = NULL;

        minfo(NO_FILE);
    }

    /* No sockets defined */
    if (logsk == NULL) {
        os_calloc(2, sizeof(logsocket), logsk);
        logsk[0].name = NULL;
        logsk[0].location = NULL;
        logsk[0].mode = 0;
        logsk[0].prefix = NULL;
        logsk[1].name = NULL;
        logsk[1].location = NULL;
        logsk[1].mode = 0;
        logsk[1].prefix = NULL;
    }

    /* Start signal handler */
    StartSIG(ARGV0);

    if (!run_foreground) {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    mdebug1(STARTED_MSG);

    /* Wait 6 seconds for the analysisd/agentd to settle */
    mdebug1("Waiting main daemons to settle.");
    sleep(6);

    /* Start the queue */
    if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQPATH);
    }

    /* Main loop */
    LogCollectorStart();
}

/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* agent daemon */

#include "shared.h"
#include "execd.h"


/* Prototypes */
static void help_execd(char * home_path) __attribute__((noreturn));


/* Print help statement */
static void help_execd(char * home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-g group] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out(" ");
    os_free(home_path);
    exit(1);
}


#ifdef WAZUH_UNIT_TESTING
__attribute((weak))
#endif
int main(int argc, char **argv)
{
    int c;
    int test_config = 0, run_foreground = 0;
    gid_t gid;
    int m_queue = 0;
    int debug_level = 0;
    pthread_t wcom_thread;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;


    while ((c = getopt(argc, argv, "Vtdhfg:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_execd(home_path);
                break;
            case 'd':
                debug_level = 1;
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument.");
                }
                group = optarg;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument.");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_execd(home_path);
                break;
        }
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("execd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group, strerror(errno), errno);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CONFIG_ERROR, cfg);
    }

    /* Exit if test_config */
    if (test_config) {
        exit(0);
    }

    /* Signal manipulation */
    StartSIG2(ARGV0, ExecdShutdown);

    if (!run_foreground) {
        /* Going daemon */
        nowDaemon();
        goDaemon();
    }

    /* Active response disabled */
    if (c == 1) {
        minfo(EXEC_DISABLED);
    }

    /* Create the PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    // Start com request thread
    if (CreateThreadJoinable(&wcom_thread, wcom_main, NULL) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* If AR is disabled, do not continue */
    if (c == 1) {
        pthread_join(wcom_thread, NULL);
        exit(EXIT_SUCCESS);
    }

    /* Start exec queue */
    if ((m_queue = StartMQ(EXECQUEUE, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, EXECQUEUE, strerror(errno));
    }

    /* The real daemon Now */
    ExecdStart(m_queue);

    exit(0);
}

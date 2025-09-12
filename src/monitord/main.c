/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config/config.h"
#include "monitord.h"
#include "os_net/os_net.h"

/* Prototypes */
static void help_monitord(char * home_path) __attribute__((noreturn));


/* Print help statement */
static void help_monitord(char * home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out("    -D <dir>    Directory to chroot and chdir into (default: %s)", home_path);
    print_out("    -n          Disable agent monitoring.");
    print_out("    -w <sec>    Time (sec.) to wait before rotating logs and alerts.");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    int no_agents = 0;
    uid_t uid;
    gid_t gid;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;
    short day_wait = -1;
    char * end;
    int debug_level = 0;

    /* Initialize global variables */
    mond.a_queue = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:nw:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_monitord(home_path);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                os_free(home_path);
                os_strdup(optarg, home_path);
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
            case 'n':
                no_agents = 1;
                break;
            case 'w':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                if (day_wait = (short)strtol(optarg, &end, 10), !end || *end || day_wait < 0 || day_wait > MAX_DAY_WAIT) {
                    merror_exit("Invalid value for option -%c.", c);
                }

                break;
            default:
                help_monitord(home_path);
                break;
        }

    }

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("monitord", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Reading configuration */
    if (MonitordConfig(cfg, &mond, no_agents, day_wait) != OS_SUCCESS ) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    // Read the cluster status and the node type from the configuration file
    // Do not monitor agents in client/worker nodes
    switch (w_is_worker()){
        case 0:
            worker_node = false;
            break;
        case 1:
            mdebug1("Cluster client node: Disabled the agent monitoring");
            worker_node = true;
            mond.monitor_agents = 0;
            break;
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Setup random */
    srandom_init();

    if (!run_foreground) {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }

    nowChroot();

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    mdebug1(PRIVSEP_MSG, home_path, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real daemon now */
    Monitord();

    os_free(home_path);
    return(0);
}

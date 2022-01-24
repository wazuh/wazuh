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
#include "agentlessd.h"
#include "config/config.h"

/* Prototypes */
static void help_agentlessd(char * home_path) __attribute__((noreturn));


/* Print help statement */
static void help_agentlessd(char * home_path)
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
    print_out("    -D <dir>    Directory to chdir and chroot into (default: %s)", home_path);
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;

    char * home_path = w_homedir(argv[0]);
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agentlessd(home_path);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument.");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument.");
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument.");
                }
                os_free(home_path);
                os_strdup(optarg, home_path);
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
                help_agentlessd(home_path);
                break;
        }
    }

    /* chdir to working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Read config */
    c = 0;
    c |= CAGENTLESS;
    lessdc.entries = NULL;
    lessdc.queue = 0;

    if (ReadConfig(c, cfg, &lessdc, NULL) < 0) {
        merror_exit(XML_INV_AGENTLESS);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Continue in daemon mode */
    if (!run_foreground) {
        nowDaemon();
        goDaemonLight();
    }

    /* Exit if not configured */
    if (!lessdc.entries) {
        minfo("Not configured. Exiting.");
        exit(0);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    mdebug1(PRIVSEP_MSG, home_path, user);

    os_free(home_path);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real daemon now */
    Agentlessd();

    return (0);
}

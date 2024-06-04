/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remoted.h"
#include "shared_download.h"
#include <unistd.h>

/* Prototypes */
static void help_remoted(char *home_path) __attribute__((noreturn));


/* Print help statement */
static void help_remoted(char *home_path)
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
    print_out("    -D <dir>    Directory to chroot into (default: %s)", home_path);
    print_out("    -m          Avoid creating shared merged file (read only)");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
    int i = 0, c = 0;
    uid_t uid;
    gid_t gid;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;
    int nocmerged = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    const char *cfg = OSSECCONF;
    const char *user = USER;
    const char *group = GROUPGLOBAL;

    while ((c = getopt(argc, argv, "Vdthfu:g:c:D:m")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_remoted(home_path);
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
            case 't':
                test_config = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c need an argument");
                }
                cfg = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                os_free(home_path);
                os_strdup(optarg, home_path);
                break;
            case 'm':
                nocmerged = 1;
                break;
            default:
                help_remoted(home_path);
                break;
        }
    }

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("remoted", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Return 0 if not configured */
    if (RemotedConfig(cfg, &logr) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    /* Exit if verify msg id is set and worker pool is greater than one */
    if ((getDefine_Int("remoted", "worker_pool", 1, 16) > 1) && (getDefine_Int("remoted", "verify_msg_id", 0, 1) == 1)) {
        merror_exit("Message id verification can't be guaranteed when worker_pool is greater than 1.");
    }

    logr.nocmerged = nocmerged ? 1 : !getDefine_Int("remoted", "merge_shared", 0, 1);

    // Read the cluster status and the node type from the configuration file
    switch (w_is_worker()){
        case 0:
            logr.worker_node = false;
            mdebug1("This is not a worker");
            break;
        case 1:
            logr.worker_node = true;
            mdebug1("Cluster worker node: Disabling the merged.mg creation");
            logr.nocmerged = 1;
            break;
    }

    if (logr.conn == NULL) {
        /* Not configured */
        merror_exit("Remoted connection is not configured.");
    }

    /* Exit if test_config is set */
    if (test_config) {
        exit(0);
    }


    /* Don't exit when client.keys empty (if set) */
    pass_empty_keyfile = getDefine_Int("remoted", "pass_empty_keyfile", 0, 1);
    if (pass_empty_keyfile) {
        OS_PassEmptyKeyfile();
    }

    /* Check if the user and group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Setup random */
    srandom_init();

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Set new group */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }
    nowChroot();
    os_free(home_path);

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    os_random();

    /* Start up message */
    mdebug2(STARTUP_MSG, (int)getpid());

    //Start shared download
    w_init_shared_download();

    /* Really start the program */
    i = 0;
    while (logr.conn[i] != 0) {
        /* Fork for each connection handler */
        if (fork() == 0) {
            /* On the child */
            mdebug1("Forking remoted: '%d'.", i);
            logr.position = i;
            HandleRemote(uid);
        } else {
            i++;
            continue;
        }
    }

    return (0);
}

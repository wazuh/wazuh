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
#include "agentd.h"

#if !defined(HPUX) && !defined(AIX) && !defined(SOLARIS)
#include <getopt.h>
#endif

#ifndef ARGV0
#define ARGV0 "wazuh-agentd"
#endif

/* Prototypes */
static void help_agentd(char *home_path) __attribute((noreturn));


/* Print help statement */
static void help_agentd(char *home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config]", ARGV0);
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
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
    int c = 0;
    int test_config = 0;
    int debug_level = 0;
    char *home_path = w_homedir(argv[0]);

    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;
    const char *uninstall_auth_login = NULL;
    const char *uninstall_auth_token = NULL;
    const char *uninstall_auth_host = NULL;
    bool ssl_verify = true;

    uid_t uid;
    gid_t gid;

    run_foreground = 0;

    /* Set the name */
    OS_SetName(ARGV0);

	/* Change working directory */
    if (chdir(home_path) == -1) {
        merror(CHDIR_ERROR, home_path, errno, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    agent_debug_level = getDefine_Int("agent", "debug", 0, 2);

#if !defined(HPUX) && !defined(AIX) && !defined(SOLARIS)
    struct option long_opts[] = {
        {"uninstall-auth-login", required_argument, NULL, 1},
        {"uninstall-auth-token", required_argument, NULL, 2},
        {"uninstall-auth-host", required_argument, NULL, 3},
        {"uninstall-ssl-verify", optional_argument, NULL, 4},
        {NULL, no_argument, NULL, 0}
    };

    while ((c = getopt_long(argc, argv, "Vtdfhu:g:D:c:", long_opts, NULL)) != -1) {
#else
    while ((c = getopt(argc, argv, "Vtdfhu:g:D:c:")) != -1) {
#endif
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agentd(home_path);
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
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                mwarn("-D is deprecated.");
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument.");
                }
                cfg = optarg;
                break;
#if !defined(HPUX) && !defined(AIX) && !defined(SOLARIS)
            case 1:
                if (!optarg) {
                    merror_exit("--uninstall-auth-login needs an argument");
                }
                uninstall_auth_login = optarg;
                break;
            case 2:
                if (!optarg) {
                    merror_exit("--uninstall-auth-token needs an argument");
                }
                uninstall_auth_token = optarg;
                break;
            case 3:
                if (!optarg) {
                    merror_exit("--uninstall-auth-host needs an argument");
                }
                uninstall_auth_host = optarg;
                break;
            case 4:
                if (!optarg || strcmp(optarg, "") == 0 || strcmp(optarg, "true") == 0 || strcmp(optarg, "TRUE") == 0 || strcmp(optarg, "1") == 0) {
                    ssl_verify = true;
                } else if (strcmp(optarg, "false") == 0 || strcmp(optarg, "FALSE") == 0 || strcmp(optarg, "0") == 0) {
                    ssl_verify = false;
                } else {
                    merror_exit("--uninstall-ssl-verify accepts 'true'/'false' or '1'/'0' as arguments");
                }
                break;
#endif
            default:
                help_agentd(home_path);
                break;
        }
    }

#if !defined(HPUX) && !defined(AIX) && !defined(SOLARIS)
    /* Anti tampering functionality */
    if ((uninstall_auth_token || uninstall_auth_login) && uninstall_auth_host) {
        exit(package_uninstall_validation(uninstall_auth_token, uninstall_auth_login, uninstall_auth_host, ssl_verify));
    }
#endif

    agt = (agent *)calloc(1, sizeof(agent));
    if (!agt) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    atc = (anti_tampering *)calloc(1, sizeof(anti_tampering));
    if (!atc) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = agent_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);
    mdebug1(STARTUP_MSG, (int)getpid());

    /* Read config */
    if (ClientConf(cfg) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!(agt->server && agt->server[0].rip)) {
        merror(AG_INV_IP);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_Address(agt->server)){
        merror(AG_INV_MNGIP, agt->server[0].rip);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_IPv6_Link_Local_Interface(agt->server)){
        merror(AG_INV_INT);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (agt->notify_time == 0) {
        agt->notify_time = NOTIFY_TIME;
    }
    if (agt->max_time_reconnect_try == 0 ) {
        agt->max_time_reconnect_try = RECONNECT_TIME;
    }
    if (agt->max_time_reconnect_try <= agt->notify_time) {
        agt->max_time_reconnect_try = (agt->notify_time * 3);
        minfo("Max time to reconnect can't be less than notify_time(%d), using notify_time*3 (%d)", agt->notify_time, agt->max_time_reconnect_try);
    }

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Exit if test config */
    if (test_config) {
        exit(0);
    }

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Agentd Start */
    AgentdStart(uid, gid, user, group);

    return (0);
}

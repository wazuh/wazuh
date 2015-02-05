/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Rootcheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 * http://www.ossec.net/rootcheck/
 */

#include "headers/shared.h"
#include "rootcheck.h"

rkconfig rootcheck;
char **rk_sys_file;
char **rk_sys_name;
int rk_sys_count;
char total_ports_udp[65535 + 1];
char total_ports_tcp[65535 + 1];

#ifndef ARGV0
#define ARGV0 "rootcheck"
#endif

#ifndef OSSECHIDS


/* Print help statement */
void help_rootcheck()
{
    print_header();
    print_out("  %s: -[Vhdtsr] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          Print this help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -s          Scan the whole system");
    print_out("    -r          Read all the files for kernel-based detection");
    print_out("    -c <config> Configuration file to use");
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int test_config = 0;
    const char *cfg = "./rootcheck.conf";

#else

int rootcheck_init(int test_config)
{
    const char *cfg = DEFAULTCPATH;

#endif /* OSSECHIDS */

    int c;

    /* Zero the structure, initialize default values */
    rootcheck.workdir = NULL;
    rootcheck.basedir = NULL;
    rootcheck.unixaudit = NULL;
    rootcheck.ignore = NULL;
    rootcheck.rootkit_files = NULL;
    rootcheck.rootkit_trojans = NULL;
    rootcheck.winaudit = NULL;
    rootcheck.winmalware = NULL;
    rootcheck.winapps = NULL;
    rootcheck.daemon = 1;
    rootcheck.notify = QUEUE;
    rootcheck.scanall = 0;
    rootcheck.readall = 0;
    rootcheck.disabled = 0;
    rootcheck.alert_msg = NULL;
    rootcheck.time = ROOTCHECK_WAIT;

    rootcheck.checks.rc_dev = 1;
    rootcheck.checks.rc_files = 1;
    rootcheck.checks.rc_if = 1;
    rootcheck.checks.rc_pids = 1;
    rootcheck.checks.rc_ports = 1;
    rootcheck.checks.rc_sys = 1;
    rootcheck.checks.rc_trojans = 1;
#ifdef WIN32
    rootcheck.checks.rc_winaudit = 1;
    rootcheck.checks.rc_winmalware = 1;
    rootcheck.checks.rc_winapps = 1;
#else
    rootcheck.checks.rc_unixaudit = 1;
#endif

    /* We store up to 255 alerts in there */
    os_calloc(256, sizeof(char *), rootcheck.alert_msg);
    c = 0;
    while (c <= 255) {
        rootcheck.alert_msg[c] = NULL;
        c++;
    }

#ifndef OSSECHIDS
    rootcheck.notify = SYSLOG;
    rootcheck.daemon = 0;
    while ((c = getopt(argc, argv, "VstrdhD:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_rootcheck();
                break;
            case 'd':
                nowDebug();
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                rootcheck.workdir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 's':
                rootcheck.scanall = 1;
                break;
            case 't':
                test_config = 1;
                break;
            case 'r':
                rootcheck.readall = 1;
                break;
            default:
                help_rootcheck();
                break;
        }
    }
#ifdef WIN32
    /* Start Winsock */
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
            ErrorExit("%s: WSAStartup() failed", ARGV0);
        }
    }
#endif /* WIN32 */

#endif /* OSSECHIDS */

    /* Start up message */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror("%s: Configuration file '%s' not found", ARGV0, cfg);
        return (-1);
    }

    /* Read configuration  --function specified twice (check makefile) */
    if (Read_Rootcheck_Config(cfg) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* If testing config, exit here */
    if (test_config) {
        return (0);
    }

    /* Return 1 disables rootcheck */
    if (rootcheck.disabled == 1) {
        verbose("%s: Rootcheck disabled. Exiting.", ARGV0);
        return (1);
    }

    /* Check if Unix audit file is configured */
    if (!rootcheck.unixaudit) {
#ifndef WIN32
        log2file("%s: System audit file not configured.", ARGV0);
#endif
    }

    /* Set default values */
    if (rootcheck.workdir == NULL) {
        rootcheck.workdir = DEFAULTDIR;
    }

#ifdef OSSECHIDS
    /* Start up message */
#ifdef WIN32
    verbose(STARTUP_MSG, "ossec-rootcheck", getpid());
#else

    /* Connect to the queue if configured to do so */
    if (rootcheck.notify == QUEUE) {
        debug1("%s: Starting queue ...", ARGV0);

        /* Start the queue */
        if ((rootcheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            merror(QUEUE_ERROR, ARGV0, DEFAULTQPATH, strerror(errno));

            /* 5 seconds to see if the agent starts */
            sleep(5);
            if ((rootcheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                /* Wait 10 more seconds */
                merror(QUEUE_ERROR, ARGV0, DEFAULTQPATH, strerror(errno));
                sleep(10);
                if ((rootcheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }
    }

#endif /* WIN32 */

#endif /* OSSECHIDS */

    /* Initialize rk list */
    rk_sys_name = (char **) calloc(MAX_RK_SYS + 2, sizeof(char *));
    rk_sys_file = (char **) calloc(MAX_RK_SYS + 2, sizeof(char *));
    if (!rk_sys_name || !rk_sys_file) {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }
    rk_sys_name[0] = NULL;
    rk_sys_file[0] = NULL;

#ifndef OSSECHIDS
#ifndef WIN32
    /* Start signal handling */
    StartSIG(ARGV0);
#endif
    debug1("%s: DEBUG: Running run_rk_check", ARGV0);
    run_rk_check();

    debug1("%s: DEBUG: Leaving...", ARGV0);
#endif /* OSSECHIDS */
    return (0);
}


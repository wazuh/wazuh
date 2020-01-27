/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config/config.h"
#include "config/reports-config.h"

/* Prototypes */
static void help_reportd(void) __attribute__((noreturn));

/* Print help statement */
static void help_reportd()
{
    print_header();
    print_out("  Generate reports (via stdin)");
    print_out("  %s: -[Vhdtns] [-u user] [-g group] [-D dir] [-f filter value] [-r filter value]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -n          Create description for the report");
    print_out("    -s          Show the alert dump");
    print_out("    -S <source> Set report source");
    print_out("    Sources allowed: log, json");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -f <filter> <value> Filter the results");
    print_out("    -r <filter> <value> Show related entries");
    print_out("    Filters allowed: group, rule, level, location,");
    print_out("                     user, srcip, filename");
    print_out("  Examples:");
    print_out("     -f group authentication_success (to filter on login success)");
    print_out("     -f level 10 (to filter on level >= 10)");
    print_out("     -f group authentication -r user srcip (to show srcip for all users)");
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, s = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;

    const char *filter_by = NULL;
    const char *filter_value = NULL;

    const char *related_of = NULL;
    const char *related_values = NULL;
    monitor_config *mon_config;

    /* Set the name */
    OS_SetName(ARGV0);

    os_calloc(1, sizeof(monitor_config), mon_config);

    ReadConfig(CREPORTS, DEFAULTCPATH, mon_config, NULL);

    /* Get any configured entry */
    if (!mon_config->reports) {
        os_calloc(1, 2 * sizeof(report_config *), mon_config->reports);
        os_calloc(1, sizeof(report_config), mon_config->reports[s]);

        mon_config->reports[s]->r_filter.report_type = 0;
    }

    while ((c = getopt(argc, argv, "Vdhstu:g:D:f:v:n:r:S:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_reportd();
                break;
            case 'd':
                nowDebug();
                break;
            case 'n':
                if (!optarg) {
                    merror_exit("-n needs an argument");
                }
                mon_config->reports[s]->r_filter.report_name = optarg;
                break;
            case 'r':
                if (!optarg || !argv[optind]) {
                    merror_exit("-r needs two argument");
                }
                related_of = optarg;
                related_values = argv[optind];

                if (os_report_configfilter(related_of, related_values,
                                           &(mon_config->reports[s]->r_filter), REPORT_RELATED)) {
                    merror_exit(CONFIG_ERROR, "user argument");
                }
                optind++;
                break;
            case 'f':
                if (!optarg) {
                    merror_exit("-f needs two argument");
                }
                filter_by = optarg;
                filter_value = argv[optind];

                if (os_report_configfilter(filter_by, filter_value,
                                           &(mon_config->reports[s]->r_filter), REPORT_FILTER)) {
                    merror_exit(CONFIG_ERROR, "user argument");
                }
                optind++;
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
                dir = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 's':
                mon_config->reports[s]->r_filter.show_alerts = 1;
                break;
            case 'S':
                if (!optarg) {
                    merror_exit("-S needs an argument");
                }
                if (strncmp(optarg, "log", 3) == 0) {
                    mon_config->reports[s]->r_filter.report_log_source = REPORT_SOURCE_LOG;
                }
                else if (strncmp(optarg, "json", 4) == 0) {
                    mon_config->reports[s]->r_filter.report_log_source = REPORT_SOURCE_JSON;
                }
                else {
                    merror_exit("-S invalid argument. Options are 'log' or 'json'");
                }
                break;
            default:
                help_reportd();
                break;
        }
    }

    /* Start daemon */
    mdebug1(STARTED_MSG);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }
    nowChroot();

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    mdebug1(PRIVSEP_MSG, dir, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real stuff now */
    os_ReportdStart(&(mon_config->reports[s]->r_filter));

    exit(0);
}


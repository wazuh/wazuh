/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef ARGV0
#undef ARGV0
#define ARGV0 "ossec-testrule"
#endif

#include "shared.h"
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "lists_make.h"
#include "eventinfo.h"
#include "analysisd.h"

/** Global definitions **/
int today;
int thishour;
int prev_year;
char prev_month[4];
int __crt_hour;
int __crt_wday;
struct timespec c_timespec;
char __shost[512];
OSDecoderInfo *NULL_Decoder;

/* print help statement */
__attribute__((noreturn))
static void help_makelists(void)
{
    print_header();
    print_out("  %s: -[VhdtF] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -F          Force rebuild of all databases");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(1);
}

#ifdef WAZUH_UNIT_TESTING
__attribute((weak))
#endif
int main(int argc, char **argv)
{
    int test_config = 0;
    int c = 0;
    const char *dir = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    uid_t uid;
    gid_t gid;
    int force = 0;

    const char *cfg = DEFAULTCPATH;

    /* Set the name */
    OS_SetName(ARGV0);

    thishour = 0;
    today = 0;
    prev_year = 0;
    memset(prev_month, '\0', 4);

    while ((c = getopt(argc, argv, "VdhFtu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_makelists();
                break;
            case 'd':
                nowDebug();
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
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 'F':
                force = 1;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_makelists();
                break;
        }
    }

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Found user */
    mdebug1(FOUND_USER);

    /* Read configuration file */
    if (GlobalConf(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    mdebug1(READ_CONFIG);

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Chroot */
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }

    nowChroot();

    if (test_config == 1) {
        exit(0);
    }

    /* Create the lists for use in rules */
    Lists_OP_CreateLists();

    /* Read the lists */
    {
        char **listfiles;
        listfiles = Config.lists;
        while (listfiles && *listfiles) {
            if (Lists_OP_LoadList(*listfiles) < 0) {
                merror_exit(LISTS_ERROR, *listfiles);
            }
            free(*listfiles);
            listfiles++;
        }
        free(Config.lists);
        Config.lists = NULL;
    }

    printf(" Since Wazuh v3.11.0, this binary is deprecated\n");
    printf(" CDB lists are now compiled at manager start-up time as well as each time ossec-logtest is run.\n");
    Lists_OP_MakeAll(force, 1);
    exit(0);
}

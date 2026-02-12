/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "manage_agents.h"
#include <stdlib.h>
#include "dll_load_notify.h"

#if defined(__MINGW32__) || defined(__hppa__)
static int setenv(const char *name, const char *val, __attribute__((unused)) int overwrite)
{
    assert(name);
    assert(val);

    int len = strlen(name) + strlen(val) + 2;
    char *str;
    os_malloc(len, str);

    snprintf(str, len, "%s=%s", name, val);
    putenv(str);

    os_free(str);

    return 0;
}
#endif

__attribute__((noreturn)) static void helpmsg()
{
    print_header();
    print_out("  %s -[Vhj] [-i id]", ARGV0);
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");
    print_out("    -j          Use JSON output.");
    print_out("    -i <key>    Import authentication key (Agent only).");
    exit(1);
}

static void print_banner()
{
    printf("\n");
    printf(BANNER, __ossec_name, __ossec_version, (int)(21 - strlen(__ossec_name) - strlen(__ossec_version)), "                     ");

    printf(BANNER_CLIENT);
    return;
}

#ifndef WIN32
/* Clean shutdown on kill */
__attribute__((noreturn)) void manage_shutdown(__attribute__((unused)) int sig)
{
    printf("\n");
    printf(EXIT);

    exit(0);
}
#endif

char shost[512];

int main(int argc, char **argv)
{
#ifdef WIN32
    // This must be always the first instruction
    enable_dll_verification();
#endif

    int c = 0, json_output = 0;
    char *user_msg;
    const char *cmdimport = NULL;
#ifndef WIN32
    const char *group = GROUPGLOBAL;
    gid_t gid;
#else
    FILE *fp;
#endif

    /* Set the name */
    OS_SetName(ARGV0);
#ifndef WIN32
    char * home_path = w_homedir(argv[0]);
    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
#endif

    while ((c = getopt(argc, argv, "Vhji:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                helpmsg();
                break;
            case 'i':
                if (!optarg) {
                    merror_exit("-i needs an argument.");
                }
                cmdimport = optarg;
                break;
            case 'j':
                json_output = 1;
                break;
            default:
                helpmsg();
                break;
        }
    }

    /* Get current time */
    time1 = time(0);

    /* Before chroot */
    srandom_init();
    getuname();

#ifndef WIN32
    if (gethostname(shost, sizeof(shost) - 1) < 0) {
        strncpy(shost, "localhost", sizeof(shost) - 1);
        shost[sizeof(shost) - 1] = '\0';
    }

    /* Get the group name */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group, strerror(errno), errno);
    }

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Chroot to the default directory */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }

    os_free(home_path);

    /* Inside chroot now */
    nowChroot();

    /* Start signal handler */
    StartSIG2(ARGV0, manage_shutdown);
#else

    w_ch_exec_dir();

    /* Check permissions */
    fp = wfopen(OSSECCONF, "r");
    if (fp) {
        fclose(fp);
    } else {
        merror_exit(CONF_ERROR, OSSECCONF);
    }
#endif

    if (cmdimport) {
        k_import(cmdimport);
        exit(0);
    }

    /* Little shell */
    while (1) {
        int leave_s = 0;

        if (!json_output)
            print_banner();

        /* Get ACTION from the environment. If ACTION is specified,
         * we must set leave_s = 1 to ensure that the loop will end */
        user_msg = getenv("OSSEC_ACTION");
        if (user_msg == NULL) {
            user_msg = read_from_user();
        } else {
            leave_s = 1;
        }

        /* All the allowed actions */
        switch (user_msg[0]) {
            case 'i':
            case 'I':
                k_import(NULL);
                break;
            case 'q':
            case 'Q':
                leave_s = 1;
                break;
            case 'V':
                print_version();
                break;
            default:
                printf("\n ** Invalid Action ** \n\n");
                break;
        }

        if (leave_s) {
            break;
        }

        continue;
    }

    if (!json_output) {
        printf("\n");
        printf(EXIT);
    }

    return (0);
}

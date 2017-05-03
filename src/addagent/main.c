/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "manage_agents.h"
#include <stdlib.h>

#if defined(__MINGW32__)
static int setenv(const char *name, const char *val, __attribute__((unused)) int overwrite)
{
    int len = strlen(name) + strlen(val) + 2;
    char *str = (char *)malloc(len);
    snprintf(str, len, "%s=%s", name, val);
    putenv(str);
    return 0;
}
#endif

__attribute__((noreturn)) static void helpmsg()
{
    print_header();
    print_out("  %s: -[Vhlj] [-a <ip> -n <name>] [-d sec] [-e id] [-r id] [-i id] [-f file]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -j          Use JSON output");
    print_out("    -l          List available agents");
    print_out("    -a <ip>     Add new agent");
    print_out("    -e <id>     Extracts key for an agent (Manager only)");
    print_out("    -r <id>     Remove an agent (Manager only)");
    print_out("    -i <id>     Import authentication key (Agent only)");
    print_out("    -n <name>   Name for new agent");
    print_out("    -d <sec>    Remove agents with duplicated IP if disconnected since <sec> seconds");
    print_out("    -f <file>   Bulk generate client keys from file (Manager only)");
    print_out("                <file> contains lines in IP,NAME format");
    exit(1);
}

static void print_banner()
{
    printf("\n");
    printf(BANNER, __ossec_name, __version, (int)(21 - strlen(__ossec_name) - strlen(__version)), "                     ");

#ifdef CLIENT
    printf(BANNER_CLIENT);
#else
    printf(BANNER_OPT);
#endif

    return;
}

#ifndef WIN32
/* Clean shutdown on kill */
__attribute__((noreturn)) void manage_shutdown(__attribute__((unused)) int sig)
{
    /* Checking if restart message is necessary */
    if (restart_necessary) {
        printf(MUST_RESTART);
    } else {
        printf("\n");
    }
    printf(EXIT);

    exit(0);
}
#endif

int main(int argc, char **argv)
{
    char *user_msg;
    int c = 0, cmdlist = 0, json_output = 0;
    int force_antiquity;
    char *end;
    const char *cmdexport = NULL;
    const char *cmdimport = NULL;
    const char *cmdbulk = NULL;
#ifndef WIN32
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    gid_t gid;
#else
    FILE *fp;
    TCHAR path[2048];
    DWORD last_error;
    int ret;
#endif

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vhle:r:i:f:ja:n:d:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                helpmsg();
                break;
            case 'e':
#ifdef CLIENT
                ErrorExit("%s: Key export only available on a master.", ARGV0);
#endif
                if (!optarg) {
                    ErrorExit("%s: -e needs an argument.", ARGV0);
                }
                cmdexport = optarg;
                break;
            case 'r':
#ifdef CLIENT
                ErrorExit("%s: Key removal only available on a master.", ARGV0);
#endif
                if (!optarg) {
                    ErrorExit("%s: -r needs an argument.", ARGV0);
                }

                /* Use environment variables already available to remove_agent() */
                setenv("OSSEC_ACTION", "r", 1);
                setenv("OSSEC_AGENT_ID", optarg, 1);
                setenv("OSSEC_ACTION_CONFIRMED", "y", 1);
                break;
            case 'i':
#ifndef CLIENT
                ErrorExit("%s: Key import only available on an agent.", ARGV0);
#endif
                if (!optarg) {
                    ErrorExit("%s: -i needs an argument.", ARGV0);
                }
                cmdimport = optarg;
                break;
            case 'f':
#ifdef CLIENT
                ErrorExit("%s: Bulk generate keys only available on a master.", ARGV0);
#endif
                if (!optarg) {
                    ErrorExit("%s: -f needs an argument.", ARGV0);
                }
                cmdbulk = optarg;
                printf("Bulk load file: %s\n", cmdbulk);
                break;
            case 'l':
                cmdlist = 1;
                break;
            case 'j':
                json_output = 1;
                break;
            case 'a':
#ifdef CLIENT
                ErrorExit("%s: Agent adding only available on a master.", ARGV0);
#endif
                if (!optarg)
                    ErrorExit("%s: -a needs an argument.", ARGV0);
                setenv("OSSEC_ACTION", "a", 1);
                setenv("OSSEC_ACTION_CONFIRMED", "y", 1);
                setenv("OSSEC_AGENT_IP", optarg, 1);
                setenv("OSSEC_AGENT_ID", "0", 1);
            break;
            case 'n':
                if (!optarg)
                    ErrorExit("%s: -n needs an argument.", ARGV0);
                setenv("OSSEC_AGENT_NAME", optarg, 1);
                break;
            case 'd':
                if (!optarg)
                    ErrorExit("%s: -d needs an argument.", ARGV0);

                force_antiquity = strtol(optarg, &end, 10);

                if (optarg == end || force_antiquity < 0)
                    ErrorExit("%s: Invalid number for -d", ARGV0);

                setenv("OSSEC_REMOVE_DUPLICATED", optarg, 1);
                break;
            default:
                helpmsg();
                break;
        }
    }

    /* Get current time */
    time1 = time(0);
    restart_necessary = 0;

    /* Before chroot */
    srandom_init();

#ifndef WIN32
    /* Get the group name */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, "", group);
    }

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Load ossec uid and gid for creating backups */
    if (OS_LoadUid() < 0) {
        ErrorExit("%s: ERROR: Couldn't get user and group id.", ARGV0);
    }

    /* Chroot to the default directory */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Inside chroot now */
    nowChroot();

    /* Start signal handler */
    StartSIG2(ARGV0, manage_shutdown);
#else
    /* Get full path to the directory this executable lives in */
    ret = GetModuleFileName(NULL, path, sizeof(path));

    /* Check for errors */
    if (!ret) {
        ErrorExit(GMF_ERROR);
    }

    /* Get last error */
    last_error = GetLastError();

    /* Look for errors */
    if (last_error != ERROR_SUCCESS) {
        if (last_error == ERROR_INSUFFICIENT_BUFFER) {
            ErrorExit(GMF_BUFF_ERROR, ret, sizeof(path));
        } else {
            ErrorExit(GMF_UNKN_ERROR, last_error);
        }
    }

    /* Remove file name from path */
    PathRemoveFileSpec(path);

    /* Move to correct directory */
    if (chdir(path)) {
        ErrorExit(CHDIR_ERROR, ARGV0, path, errno, strerror(errno));
    }

    /* Check permissions */
    fp = fopen(OSSECCONF, "r");
    if (fp) {
        fclose(fp);
    } else {
        ErrorExit(CONF_ERROR, OSSECCONF);
    }
#endif

    if (cmdlist == 1) {
        list_agents(cmdlist);
        exit(0);
    } else if (cmdimport) {
        k_import(cmdimport);
        exit(0);
    } else if (cmdexport) {
        k_extract(cmdexport, json_output);
        exit(0);
    } else if (cmdbulk) {
        k_bulkload(cmdbulk);
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
            case 'A':
            case 'a':
#ifdef CLIENT
                printf("\n ** Agent adding only available on a master ** \n\n");
                break;
#endif
                add_agent(json_output);
                break;
            case 'e':
            case 'E':
#ifdef CLIENT
                printf("\n ** Key export only available on a master ** \n\n");
                break;
#endif
                k_extract(NULL, json_output);
                break;
            case 'i':
            case 'I':
#ifdef CLIENT
                k_import(NULL);
#else
                printf("\n ** Key import only available on an agent ** \n\n");
#endif
                break;
            case 'l':
            case 'L':
                list_agents(0);
                break;
            case 'r':
            case 'R':
#ifdef CLIENT
                printf("\n ** Key removal only available on a master ** \n\n");
                break;
#endif
                remove_agent(json_output);
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
        if (restart_necessary) {
            printf(MUST_RESTART);
        } else {
            printf("\n");
        }

        printf(EXIT);
    }

    return (0);
}

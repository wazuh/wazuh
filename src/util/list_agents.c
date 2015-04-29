/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "read-agents.h"

#undef ARGV0
#define ARGV0 "list_agents"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\nOSSEC HIDS %s: List available agents.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h    This help message.\n");
    printf("\t-a    List all agents.\n");
    printf("\t-c    List the connected (active) agents.\n");
    printf("\t-n    List the not connected (active) agents.\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;

    const char *msg;
    char **agent_list;
    gid_t gid;
    uid_t uid;
    int flag = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    /* Get the group name */
    gid = Privsep_GetGroup(group);
    uid = Privsep_GetUser(user);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Chroot to the default directory */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Inside chroot now */
    nowChroot();

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* User options */
    if (strcmp(argv[1], "-h") == 0) {
        helpmsg();
    } else if (strcmp(argv[1], "-a") == 0) {
        flag = GA_ALL;
        msg = "is available.";
    } else if (strcmp(argv[1], "-c") == 0) {
        flag = GA_ACTIVE;
        msg = "is active.";
    } else if (strcmp(argv[1], "-n") == 0) {
        flag = GA_NOTACTIVE;
        msg = "is not active.";
    } else {
        printf("\n** Invalid option '%s'.\n", argv[1]);
        helpmsg();
    }

    agent_list = get_agents(flag);
    if (agent_list) {
        char **agent_list_pt = agent_list;

        while (*agent_list) {
            printf("%s %s\n", *agent_list, msg);
            agent_list++;
        }

        free_agents(agent_list_pt);
    } else {
        printf("** No agent available.\n");
    }
    return (0);
}


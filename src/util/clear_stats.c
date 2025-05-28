/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* This tool will clear the event statistics */

#include "shared.h"

#undef ARGV0
#define ARGV0 "clear_stats"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\n%s %s: Clear the events stats (averages).\n", __ossec_name, ARGV0);
    printf("Available options:\n");
    printf("\t-h       This help message.\n");
    printf("\t-a       Clear all the stats (averages).\n");
    printf("\t-d       Clear the daily averages.\n");
    printf("\t-w       Clear the weekly averages.\n\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int clear_daily = 0;
    int clear_weekly = 0;

    const char *group = GROUPGLOBAL;
    const char *user = USER;
    gid_t gid;
    uid_t uid;

    /* Set the name */
    OS_SetName(ARGV0);

    /* Define current working directory */
    char * home_path = w_homedir(argv[0]);
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
    mdebug1(WAZUH_HOMEDIR, home_path);

    /* user arguments */
    if (argc != 2) {
        helpmsg();
    }

    /* Get the group name */
    gid = Privsep_GetGroup(group);
    uid = Privsep_GetUser(user);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
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

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* User options */
    if (strcmp(argv[1], "-h") == 0) {
        helpmsg();
    } else if (strcmp(argv[1], "-a") == 0) {
        clear_daily = 1;
        clear_weekly = 1;
    } else if (strcmp(argv[1], "-d") == 0) {
        clear_daily = 1;
    } else if (strcmp(argv[1], "-w") == 0) {
        clear_weekly = 1;
    } else {
        printf("\n** Invalid option '%s'.\n", argv[1]);
        helpmsg();
    }

    /* Clear daily files */
    if (clear_daily) {
        const char *daily_dir = STATQUEUE;
        DIR *daily;
        struct dirent *entry = NULL;

        daily = wopendir(daily_dir);
        if (!daily) {
            merror_exit("Unable to open: '%s'", daily_dir);
        }

        while ((entry = readdir(daily)) != NULL) {
            char full_path[OS_MAXSTR + 1];

            /* Do not even attempt to delete . and .. :) */
            if ((strcmp(entry->d_name, ".") == 0) ||
                    (strcmp(entry->d_name, "..") == 0)) {
                continue;
            }

            /* Remove file */
            full_path[OS_MAXSTR] = '\0';
            snprintf(full_path, OS_MAXSTR, "%s/%s", daily_dir, entry->d_name);
            unlink(full_path);
        }

        closedir(daily);
    }

    /* Clear weekly averages */
    if (clear_weekly) {
        int i = 0;
        while (i <= 6) {
            const char *daily_dir = STATWQUEUE;
            char dir_path[PATH_MAX + 1];
            DIR *daily;
            struct dirent *entry = NULL;

            snprintf(dir_path, PATH_MAX, "%s/%d", daily_dir, i);
            daily = wopendir(dir_path);
            if (!daily) {
                merror_exit("Unable to open: '%s' (no stats)", dir_path);
            }

            while ((entry = readdir(daily)) != NULL) {
                char full_path[OS_MAXSTR + 1];

                /* Do not even attempt to delete . and .. :) */
                if ((strcmp(entry->d_name, ".") == 0) ||
                        (strcmp(entry->d_name, "..") == 0)) {
                    continue;
                }

                /* Remove file */
                full_path[OS_MAXSTR] = '\0';
                snprintf(full_path, OS_MAXSTR, "%s/%s", dir_path,
                         entry->d_name);
                unlink(full_path);
            }

            i++;
            closedir(daily);
        }
    }

    printf("\n** Internal stats clear.\n\n");

    return (0);
}

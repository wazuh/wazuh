/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "addagent/manage_agents.h"
#include "sec.h"
#include "wazuh_db/wdb.h"

#undef ARGV0
#define ARGV0 "syscheck_update"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\n%s %s: This binary it's deprecated, use API calls related below instead.\n", __ossec_name, ARGV0);
    printf("Available options:\n");
    printf("\t-h       This help message.\n");
    printf("\t-l       List available agents. Use https://documentation.wazuh.com/current/user-manual/api/reference.html#get-all-agents filtering by status.\n");
    printf("\t-a       Update (clear) syscheck database for all agents. Use https://documentation.wazuh.com/current/user-manual/api/reference.html#clear-syscheck-database.\n");
    printf("\t-u <id>  Update (clear) syscheck database for a specific agent. Use https://documentation.wazuh.com/current/user-manual/api/reference.html#clear-syscheck-database-of-an-agent.\n");
    printf("\t-u local Update (clear) syscheck database locally. Use https://documentation.wazuh.com/current/user-manual/api/reference.html#clear-syscheck-database-of-an-agent with id 0.\n\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;
    gid_t gid;
    uid_t uid;

    //This binary its deprecated, use RestFull API instead
    helpmsg();

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    srandom_init();

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
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }

    /* Inside chroot now */
    nowChroot();

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* User options */
    if (strcmp(argv[1], "-h") == 0) {
        helpmsg();
    } else if (strcmp(argv[1], "-l") == 0) {
        printf("\n%s %s: Updates the integrity check database.",
               __ossec_name, ARGV0);
        print_agents(0, 0, 0, 0, 0);
        printf("\n");
        exit(0);
    } else if (strcmp(argv[1], "-u") == 0) {
        if (argc != 3) {
            printf("\n** Option -u requires an extra argument\n");
            helpmsg();
        }
    } else if (strcmp(argv[1], "-a") == 0) {
        DIR *sys_dir;
        struct dirent *entry = NULL;

        sys_dir = opendir(SYSCHECK_DIR);
        if (!sys_dir) {
            merror_exit("Unable to open: '%s'", SYSCHECK_DIR);
        }

        while ((entry = readdir(sys_dir)) != NULL) {
            FILE *fp;
            char full_path[OS_MAXSTR + 1];

            /* Do not even attempt to delete . and .. :) */
            if ((strcmp(entry->d_name, ".") == 0) ||
                    (strcmp(entry->d_name, "..") == 0)) {
                continue;
            }

            snprintf(full_path, OS_MAXSTR, "%s/%s", SYSCHECK_DIR, entry->d_name);

            fp = fopen(full_path, "w");
            if (fp) {
                fclose(fp);
            }
            if (entry->d_name[0] == '.') {
                unlink(full_path);
            }
        }

        closedir(sys_dir);
        wdb_delete_fim_all();

        printf("\n** Integrity check database updated. Restart the manager to apply changes.\n\n");
        exit(0);
    } else {
        printf("\n** Invalid option '%s'.\n", argv[1]);
        helpmsg();
    }

    /* Local */
    if (strcmp(argv[2], "local") == 0) {
        char final_dir[1024];
        FILE *fp;
        snprintf(final_dir, 1020, "/%s/syscheck", SYSCHECK_DIR);

        fp = fopen(final_dir, "w");
        if (fp) {
            fclose(fp);
        }
        unlink(final_dir);

        /* Delete cpt file */
        snprintf(final_dir, 1020, "/%s/.syscheck.cpt", SYSCHECK_DIR);

        fp = fopen(final_dir, "w");
        if (fp) {
            fclose(fp);
        }
        /* unlink(final_dir); */

        wdb_delete_fim(0);
    }

    /* External agents */
    else {
        int i;
        keystore keys = KEYSTORE_INITIALIZER;

        OS_ReadKeys(&keys, 1, 0);

        i = OS_IsAllowedID(&keys, argv[2]);
        if (i < 0) {
            printf("\n** Invalid agent id '%s'.\n", argv[2]);
            helpmsg();
        }

        /* Delete syscheck */
        delete_syscheck(keys.keyentries[i]->name, keys.keyentries[i]->ip->ip, 0);
        wdb_delete_fim(atoi(keys.keyentries[i]->id));
    }

    printf("\n** Integrity check database updated. Restart the manager to apply changes.\n\n");
    return (0);
}

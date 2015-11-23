/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "addagent/manage_agents.h"
#include "sec.h"

#undef ARGV0
#define ARGV0 "rootcheck_control"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\nOSSEC HIDS %s: Manages the policy and auditing database.\n",
           ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-l          List available (active or not) agents.\n");
    printf("\t-lc         List only active agents.\n");
    printf("\t-u <id>     Updates (clear) the database for the agent.\n");
    printf("\t-u all      Updates (clear) the database for all agents.\n");
    printf("\t-i <id>     Prints database for the agent.\n");
    printf("\t-r          Used with -i, prints all the resolved issues.\n");
    printf("\t-q          Used with -i, prints all the outstanding issues.\n");
    printf("\t-L          Used with -i, prints the last scan.\n");
    printf("\t-s          Changes the output to CSV (comma delimited).\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;
    const char *agent_id = NULL;

    gid_t gid;
    uid_t uid;
    int c = 0, info_agent = 0, update_rootcheck = 0,
        list_agents = 0, show_last = 0,
        resolved_only = 0;
    int active_only = 0, csv_output = 0;

    char shost[512];

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    while ((c = getopt(argc, argv, "VhqrDdLlcsu:i:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                helpmsg();
                break;
            case 'D':
                nowDebug();
                break;
            case 'l':
                list_agents++;
                break;
            case 's':
                csv_output = 1;
                break;
            case 'c':
                active_only++;
                break;
            case 'r':
                resolved_only = 1;
                break;
            case 'q':
                resolved_only = 2;
                break;
            case 'L':
                show_last = 1;
                break;
            case 'i':
                info_agent++;
                if (!optarg) {
                    merror("%s: -u needs an argument", ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                break;
            case 'u':
                if (!optarg) {
                    merror("%s: -u needs an argument", ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                update_rootcheck = 1;
                break;
            default:
                helpmsg();
                break;
        }

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

    /* Get server hostname */
    memset(shost, '\0', 512);
    if (gethostname(shost, 512 - 1) != 0) {
        strncpy(shost, "localhost", 32);
        return (0);
    }

    /* List available agents */
    if (list_agents) {
        if (!csv_output) {
            printf("\nOSSEC HIDS %s. List of available agents:",
                   ARGV0);
            printf("\n   ID: 000, Name: %s (server), IP: 127.0.0.1, "
                   "Active/Local\n", shost);
        } else {
            printf("000,%s (server),127.0.0.1,Active/Local,\n", shost);
        }
        print_agents(1, active_only, csv_output);
        printf("\n");
        exit(0);
    }

    /* Update rootcheck database */
    if (update_rootcheck) {
        /* Clean all agents (and server) db */
        if (strcmp(agent_id, "all") == 0) {
            DIR *sys_dir;
            struct dirent *entry;

            sys_dir = opendir(ROOTCHECK_DIR);
            if (!sys_dir) {
                ErrorExit("%s: Unable to open: '%s'", ARGV0, ROOTCHECK_DIR);
            }

            while ((entry = readdir(sys_dir)) != NULL) {
                FILE *fp;
                char full_path[OS_MAXSTR + 1];

                /* Do not even attempt to delete . and .. :) */
                if ((strcmp(entry->d_name, ".") == 0) ||
                        (strcmp(entry->d_name, "..") == 0)) {
                    continue;
                }

                snprintf(full_path, OS_MAXSTR, "%s/%s", ROOTCHECK_DIR,
                         entry->d_name);

                fp = fopen(full_path, "w");
                if (fp) {
                    fclose(fp);
                }
                if (entry->d_name[0] == '.') {
                    unlink(full_path);
                }
            }

            closedir(sys_dir);
            printf("\n** Policy and auditing database updated.\n\n");
            exit(0);
        }

        else if ((strcmp(agent_id, "000") == 0) ||
                 (strcmp(agent_id, "local") == 0)) {
            char final_dir[1024];
            FILE *fp;
            snprintf(final_dir, 1020, "/%s/rootcheck", ROOTCHECK_DIR);

            fp = fopen(final_dir, "w");
            if (fp) {
                fclose(fp);
            }
            unlink(final_dir);
            printf("\n** Policy and auditing database updated.\n\n");
            exit(0);
        }

        /* Database from remote agents */
        else {
            int i;
            keystore keys;

            OS_ReadKeys(&keys);

            i = OS_IsAllowedID(&keys, agent_id);
            if (i < 0) {
                printf("\n** Invalid agent id '%s'.\n", agent_id);
                helpmsg();
            }

            /* Delete syscheck */
            delete_rootcheck(keys.keyentries[i]->name,
                             keys.keyentries[i]->ip->ip, 0);

            printf("\n** Policy and auditing database updated.\n\n");
            exit(0);
        }
    }

    /* Print information from an agent */
    if (info_agent) {
        int i;
        char final_ip[IPSIZE + 4];
        keystore keys;

        if ((strcmp(agent_id, "000") == 0) ||
                (strcmp(agent_id, "local") == 0)) {
            if (!csv_output)
                printf("\nPolicy and auditing events for local system '%s - %s':\n",
                       shost, "127.0.0.1");

            print_rootcheck(NULL,
                            NULL, NULL, resolved_only, csv_output, show_last);
        } else {
            OS_ReadKeys(&keys);

            i = OS_IsAllowedID(&keys, agent_id);
            if (i < 0) {
                printf("\n** Invalid agent id '%s'.\n", agent_id);
                helpmsg();
            }

            /* Getting full address/prefixlength from ip. */
            final_ip[(sizeof final_ip) - 1] = '\0';
            snprintf(final_ip, sizeof final_ip, "%s/%u",
                     keys.keyentries[i]->ip->ip,
                     keys.keyentries[i]->ip->prefixlength);

            if (!csv_output)
                printf("\nPolicy and auditing events for agent "
                       "'%s (%s) - %s':\n",
                       keys.keyentries[i]->name, keys.keyentries[i]->id,
                       final_ip);

            print_rootcheck(keys.keyentries[i]->name,
                            keys.keyentries[i]->ip->ip, NULL,
                            resolved_only, csv_output, show_last);

        }

        exit(0);
    }

    printf("\n** Invalid argument combination.\n");
    helpmsg();

    return (0);
}


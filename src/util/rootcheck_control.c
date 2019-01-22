/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "addagent/manage_agents.h"
#include "sec.h"
#include "wazuh_db/wdb.h"
#include <external/cJSON/cJSON.h>

#undef ARGV0
#define ARGV0 "rootcheck_control"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\n%s %s: Manages the policy and auditing database.\n",
           __ossec_name, ARGV0);
    printf("Available options:\n\n");
    printf("\t-h          This help message.\n");
    printf("\t-V          Print version.\n");
    printf("\t-D          Debug mode.\n\n");
    printf("\t-l          List available (active or not) agents.\n");
    printf("\t-lc         List only active agents.\n");
    printf("\t-lc         List only disconnected agents.\n");
    printf("\t-u <id>     Updates (clear) the database for the agent.\n");
    printf("\t-u all      Updates (clear) the database for all agents.\n");
    printf("\t-i <id>     Prints database for the agent.\n");
    printf("\t-r          Used with -i, prints all the resolved issues.\n");
    printf("\t-q          Used with -i, prints all the outstanding issues.\n");
    printf("\t-L          Used with -i, prints the last scan.\n");
    printf("\t-s          Changes the output to CSV (comma delimited).\n");
    printf("\t-j          Changes the output to JSON.\n");
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
    int active_only = 0, csv_output = 0, json_output = 0;
    int inactive_only = 0;

    char shost[512];
    cJSON *json_root = NULL;

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    while ((c = getopt(argc, argv, "VhqrDdLlcsju:i:n")) != -1) {
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
            case 'j':
                json_output = 1;
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
                    merror("-u needs an argument");
                    helpmsg();
                }
                agent_id = optarg;
                break;
            case 'u':
                if (!optarg) {
                    merror("-u needs an argument");
                    helpmsg();
                }
                agent_id = optarg;
                update_rootcheck = 1;
                break;
            case 'n':
                inactive_only++;
                break;
            default:
                helpmsg();
                break;
        }

    }

    if (json_output)
        json_root = cJSON_CreateObject();

    srandom_init();

    /* Get the group name */
    gid = Privsep_GetGroup(group);
    uid = Privsep_GetUser(user);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group);
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

    /* Get server hostname */
    memset(shost, '\0', 512);
    if (gethostname(shost, 512 - 1) != 0) {
        strncpy(shost, "localhost", 32);
        return (0);
    }

    /* List available agents */
    if (list_agents) {
        if (!csv_output) {
            printf("\n%s %s. List of available agents:",
                   __ossec_name, ARGV0);

            if (inactive_only) {
                puts("");
            } else {
                printf("\n   ID: 000, Name: %s (server), IP: 127.0.0.1, Active/Local\n", shost);
            }
        } else if (!inactive_only) {
            printf("000,%s (server),127.0.0.1,Active/Local,\n", shost);
        }
        print_agents(1, active_only, inactive_only, csv_output, 0);
        printf("\n");
        exit(0);
    }

    /* Update rootcheck database */
    if (update_rootcheck) {
        char json_buffer[1024];

        /* Clean all agents (and server) db */
        if (strcmp(agent_id, "all") == 0) {
            DIR *sys_dir;
            struct dirent *entry;

            sys_dir = opendir(ROOTCHECK_DIR);
            if (!sys_dir) {
                if (json_output) {
                    cJSON_AddNumberToObject(json_root, "error", 11);
                    snprintf(json_buffer, 1023, "%s: Unable to open: '%s'", ARGV0, ROOTCHECK_DIR);
                    cJSON_AddStringToObject(json_root, "message", json_buffer);
                    printf("%s", cJSON_PrintUnformatted(json_root));
                    exit(1);
                } else
                    merror_exit("Unable to open: '%s'", ROOTCHECK_DIR);
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
            wdb_delete_pm_all();

            if (json_output) {
                cJSON_AddNumberToObject(json_root, "error", 0);
                cJSON_AddStringToObject(json_root, "data", "Policy and auditing database updated. Restart the manager to apply changes.");
                printf("%s", cJSON_PrintUnformatted(json_root));
            } else
                printf("\n** Policy and auditing database updated. Restart the manager to apply changes.\n\n");

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

            wdb_delete_pm(0);

            if (json_output) {
                cJSON_AddNumberToObject(json_root, "error", 0);
                cJSON_AddStringToObject(json_root, "data", "Policy and auditing database updated. Restart the manager to apply changes.");
                printf("%s", cJSON_PrintUnformatted(json_root));
            } else
                printf("\n** Policy and auditing database updated. Restart the manager to apply changes.\n\n");

            exit(0);
        }

        /* Database from remote agents */
        else {
            int i;
            keystore keys = KEYSTORE_INITIALIZER;

            OS_ReadKeys(&keys, 1, 0, 0);

            i = OS_IsAllowedID(&keys, agent_id);
            if (i < 0) {
                if (json_output) {
                    cJSON_AddNumberToObject(json_root, "error", 12);
                    snprintf(json_buffer, 1023, "Invalid agent id '%s'.", agent_id);
                    cJSON_AddStringToObject(json_root, "message", json_buffer);
                    printf("%s", cJSON_PrintUnformatted(json_root));
                    exit(1);
                } else {
                    printf("\n** Invalid agent id '%s'.\n", agent_id);
                    helpmsg();
                }
            }

            /* Delete syscheck */
            delete_rootcheck(keys.keyentries[i]->name,
                             keys.keyentries[i]->ip->ip, 0);

            wdb_delete_pm(atoi(keys.keyentries[i]->id));

            if (json_output) {
                 cJSON_AddNumberToObject(json_root, "error", 0);
                 cJSON_AddStringToObject(json_root, "data", "Policy and auditing database updated. Restart the manager to apply changes.");
                 printf("%s", cJSON_PrintUnformatted(json_root));
            } else
                printf("\n** Policy and auditing database updated. Restart the manager to apply changes.\n\n");

            exit(0);
        }
    }

    /* Print information from an agent */
    if (info_agent) {
        int i;
        char final_ip[128 + 1];
        char final_mask[128 + 1];
        keystore keys = KEYSTORE_INITIALIZER;
        cJSON *json_events = NULL;

        if (json_output)
            json_events = cJSON_CreateArray();

        if ((strcmp(agent_id, "000") == 0) ||
                (strcmp(agent_id, "local") == 0)) {
            if (!(csv_output || json_output))
                printf("\nPolicy and auditing events for local system '%s - %s':\n",
                       shost, "127.0.0.1");

            print_rootcheck(NULL, NULL, NULL, resolved_only, csv_output,
                            json_events, show_last);

            if (json_output) {
                cJSON_AddNumberToObject(json_root, "error", 0);
                cJSON_AddItemToObject(json_root, "data", json_events);
                printf("%s", cJSON_PrintUnformatted(json_root));
            }
        } else {
            OS_ReadKeys(&keys, 1, 0, 0);

            i = OS_IsAllowedID(&keys, agent_id);
            if (i < 0) {
                if (json_output) {
                    char json_buffer[1024];
                    snprintf(json_buffer, 1023, "Invalid agent id '%s'", agent_id);
                    cJSON_AddNumberToObject(json_root, "error", 13);
                    cJSON_AddStringToObject(json_root, "message", json_buffer);
                    printf("%s", cJSON_PrintUnformatted(json_root));
                    exit(1);
                } else {
                    printf("\n** Invalid agent id '%s'.\n", agent_id);
                    helpmsg();
                }
            }

            final_ip[128] = '\0';
            final_mask[128] = '\0';
            getNetmask(keys.keyentries[i]->ip->netmask,
                       final_mask, 128);
            snprintf(final_ip, 128, "%s%s", keys.keyentries[i]->ip->ip,
                     final_mask);

            if (!(csv_output || json_output))
                printf("\nPolicy and auditing events for agent "
                       "'%s (%s) - %s':\n",
                       keys.keyentries[i]->name, keys.keyentries[i]->id,
                       final_ip);

            print_rootcheck(keys.keyentries[i]->name,
                            keys.keyentries[i]->ip->ip, NULL,
                            resolved_only, csv_output, json_events, show_last);

            if (json_output) {
                cJSON_AddNumberToObject(json_root, "error", 0);
                cJSON_AddItemToObject(json_root, "data", json_events);
                printf("%s", cJSON_PrintUnformatted(json_root));
            }
        }

        exit(0);
    }

    if (json_output) {
        cJSON_AddNumberToObject(json_root, "error", 10);
        cJSON_AddStringToObject(json_root, "message", "Invalid argument combination");
        printf("%s", cJSON_PrintUnformatted(json_root));
        exit(1);
    } else {
        printf("\n** Invalid argument combination.\n");
        helpmsg();
    }

    return (0);
}

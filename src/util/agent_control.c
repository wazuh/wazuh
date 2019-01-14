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
#include "external/cJSON/cJSON.h"

#undef ARGV0
#define ARGV0 "agent_control"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));

static void helpmsg()
{
    printf("\n%s %s: Control remote agents.\n", __ossec_name, ARGV0);
    printf("Available options:\n");
    printf("\t-h                This help message.\n");
    printf("\t-l                List available (active or not) agents.\n");
    printf("\t-lc               List active agents only.\n");
    printf("\t-ln               List disconnected agents only.\n");
    printf("\t-i <id>           Extracts information from an agent.\n");
    printf("\t-R -a             Restart all agents.\n");
    printf("\t-R -u <id>        Restart the specified agent.\n");
    printf("\t-r -a             Runs the integrity/rootkit checking on all agents now.\n");
    printf("\t-r -u <id>        Runs the integrity/rootkit checking on one agent now.\n\n");
    printf("\t-s                Changes the output to CSV (comma delimited).\n");
    printf("\t-j                Changes the output to JSON .\n");
    printf("\t-m                Show the limit of agents that can be added.\n");
    printf("Available options for active response:\n");
    printf("\t-b <ip>           Blocks the specified ip address.\n");
    printf("\t-f <ar> -a        Used with -b, specifies which response to run. Apply AR on all agents.\n");
    printf("\t-f <ar> -u <id>   Used with -b, specifies which response to run. Apply AR on specified agent.\n");
    printf("\t-L                List available active responses.\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;
    const char *agent_id = NULL;
    const char *ip_address = NULL;
    const char *ar = NULL;

    cJSON *root = NULL;

    int arq = 0;
    gid_t gid;
    uid_t uid;
    int c = 0;
    int restart_syscheck = 0;
    int restart_all_agents = 0;
    int list_agents = 0;
    int info_agent = 0;
    int agt_id = 0;
    int active_only = 0;
    int csv_output = 0;
    int json_output = 0;
    int list_responses = 0;
    int end_time = 0;
    int restart_agent = 0;
    int show_max_agents = 0;
    int inactive_only = 0;

    char shost[512];

    keystore keys = KEYSTORE_INITIALIZER;

    /* Set the name */
    OS_SetName(ARGV0);

    int is_worker = w_is_worker();
    char *master;

    switch (is_worker) {
        case -1:
            merror("Invalid option at cluster configuration");
            return 0;
        case 1:
            master = get_master_node();
            merror("Wazuh is running in cluster mode: %s is not available in worker nodes. Please, try again in the master node: %s.", ARGV0, master);
            free(master);
            return 0;
    }

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    while ((c = getopt(argc, argv, "VehdlLcsjarmu:i:b:f:Rn")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                helpmsg();
                break;
            case 'd':
                nowDebug();
                break;
            case 'L':
                list_responses = 1;
                break;
            case 'e':
                end_time = 1;
                break;
            case 'r':
                restart_syscheck = 1;
                break;
            case 'l':
                list_agents++;
                break;
            case 'm':
                show_max_agents++;
                break;
            case 's':
                csv_output = 1;
                json_output = 0;
                break;
            case 'j':
                json_output = 1;
                csv_output = 0;
                break;
            case 'c':
                active_only++;
                break;
            case 'i':
                info_agent++;
                if (!optarg) {
                    merror("-i needs an argument");
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
                break;
            case 'b':
                if (!optarg) {
                    merror("-b needs an argument");
                    helpmsg();
                }
                ip_address = optarg;
                break;
            case 'f':
                if (!optarg) {
                    merror("-e needs an argument");
                    helpmsg();
                }
                ar = optarg;
                break;
            case 'R':
                restart_agent = 1;
                break;
            case 'a':
                restart_all_agents = 1;
                break;
            case 'n':
                inactive_only++;
                break;
            default:
                helpmsg();
                break;
        }

    }

    /* Prepare JSON Structure */
    if(json_output)
        root = cJSON_CreateObject();

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

    /* List responses */
    if (list_responses) {
        FILE *fp;
        if (!csv_output && !json_output) {
            printf("\n%s %s. Available active responses:\n", __ossec_name, ARGV0);
        }

        fp = fopen(DEFAULTAR, "r");
        if (fp) {
            char buffer[256];

            while (fgets(buffer, 255, fp) != NULL) {
                char *r_name;
                char *r_cmd;
                char *r_timeout;

                r_name = buffer;
                r_cmd = strchr(buffer, ' ');
                if (!r_cmd) {
                    continue;
                }

                *r_cmd = '\0';
                r_cmd++;
                if (*r_cmd == '-') {
                    r_cmd++;
                }
                if (*r_cmd == ' ') {
                    r_cmd++;
                }

                r_timeout = strchr(r_cmd, ' ');
                if (!r_timeout) {
                    continue;
                }
                *r_timeout = '\0';

                if (strcmp(r_name, "restart-ossec0") == 0) {
                    continue;
                }
                printf("\n   Response name: %s, command: %s", r_name, r_cmd);
            }

            printf("\n\n");
            fclose(fp);
        } else {
            printf("\n   No active response available.\n\n");
        }

        exit(0);
    }

    /* List available agents */
    if (list_agents) {
        cJSON *agents = NULL;

        if (!csv_output && !json_output) {
            printf("\n%s %s. List of available agents:",
                   __ossec_name, ARGV0);

            if (inactive_only) {
                puts("");
            } else {
                printf("\n   ID: 000, Name: %s (server), IP: 127.0.0.1, Active/Local\n", shost);
            }
        } else if(json_output){
                cJSON *first;
                agents = cJSON_CreateArray();

                if (!(root && agents))
                    exit(1);

                cJSON_AddNumberToObject(root, "error", 0);
                cJSON_AddItemToObject(root, "data", agents);

                if (!inactive_only) {
                    first = cJSON_CreateObject();
                    cJSON_AddStringToObject(first, "id", "000");
                    cJSON_AddStringToObject(first, "name", shost);
                    cJSON_AddStringToObject(first, "ip", "127.0.0.1");
                    cJSON_AddStringToObject(first, "status", "Active");
                    cJSON_AddItemToArray(agents, first);
                }
        } else if (!inactive_only) {
            printf("000,%s (server),127.0.0.1,Active/Local,\n", shost);
        }

        print_agents(1, active_only, inactive_only, csv_output, agents);
        // Closing JSON Object array
        if(json_output) {
            char *render = cJSON_PrintUnformatted(root);
            printf("%s", render);
            cJSON_Delete(root);
            free(render);
        } else
            printf("\n");
        exit(0);
    }

    /* Show limit of agents */

    if (show_max_agents) {
        if (json_output) {
            cJSON *data = cJSON_CreateObject();

            if (!(root && data)) {
                exit(1);
            }

            cJSON_AddNumberToObject(data, "max_agents", MAX_AGENTS);
            cJSON_AddNumberToObject(root, "error", 0);
            cJSON_AddItemToObject(root, "data", data);

            char *render = cJSON_PrintUnformatted(root);
            printf("%s", render);
            cJSON_Delete(root);
            free(render);
        } else if (csv_output) {
            printf("%d\n", MAX_AGENTS);
        } else {
            printf("Limit of agents: %d\n", MAX_AGENTS);
        }

        exit(0);
    }

    /* Check if the provided ID is valid */
    if (agent_id != NULL) {
        if (strcmp(agent_id, "000") != 0) {
            OS_PassEmptyKeyfile();
            OS_ReadKeys(&keys, 1, 0, 0);

            agt_id = OS_IsAllowedID(&keys, agent_id);
            if (agt_id < 0) {
                if(json_output){
                    cJSON_AddNumberToObject(root, "error", 40);
                    cJSON_AddStringToObject(root, "message", "Invalid agent id");
                    printf("%s",cJSON_PrintUnformatted(root));
                    cJSON_Delete(root);
                    exit(0);
                }else{
                  printf("\n** Invalid agent id '%s'.\n", agent_id);
                  helpmsg();
                }
            }
        } else {
            /* server */
            agt_id = -1;
        }
    }

    /* Print information from an agent */
    if (info_agent) {
        agent_status_t agt_status = 0;
        char final_ip[128 + 1];
        char final_mask[128 + 1];
        agent_info *agt_info;
        final_ip[128] = '\0';
        final_mask[128] = '\0';
        cJSON *json_data = cJSON_CreateObject();

        if (!csv_output && !json_output) {
            printf("\n%s %s. Agent information:", __ossec_name, ARGV0);
        }

        if (agt_id != -1) {
            agt_status = get_agent_status(keys.keyentries[agt_id]->name,
                                          keys.keyentries[agt_id]->ip->ip);

            agt_info = get_agent_info(keys.keyentries[agt_id]->name,
                                      keys.keyentries[agt_id]->ip->ip,
                                      agent_id);

            /* Get netmask from IP */
            getNetmask(keys.keyentries[agt_id]->ip->netmask, final_mask, 128);
            snprintf(final_ip, 128, "%s%s", keys.keyentries[agt_id]->ip->ip,
                     final_mask);

            if (!csv_output && !json_output) {
                printf("\n   Agent ID:   %s\n", keys.keyentries[agt_id]->id);
                printf("   Agent Name: %s\n", keys.keyentries[agt_id]->name);
                printf("   IP address: %s\n", final_ip);
                printf("   Status:     %s\n\n", print_agent_status(agt_status));
            }else if(json_output){
                cJSON_AddStringToObject(json_data, "id", keys.keyentries[agt_id]->id);
                cJSON_AddStringToObject(json_data, "name", keys.keyentries[agt_id]->name);
                cJSON_AddStringToObject(json_data, "ip", final_ip);
                cJSON_AddStringToObject(json_data, "status", print_agent_status(agt_status));
            } else {
                printf("%s,%s,%s,%s,",
                       keys.keyentries[agt_id]->id,
                       keys.keyentries[agt_id]->name,
                       final_ip,
                       print_agent_status(agt_status));
            }
        } else {
            agt_status = get_agent_status(NULL, NULL);
            agt_info = get_agent_info(NULL, "127.0.0.1", "000");

            if (!csv_output && !json_output) {
                printf("\n   Agent ID:   000 (local instance)\n");
                printf("   Agent Name: %s\n", shost);
                printf("   IP address: 127.0.0.1\n");
                printf("   Status:     %s/Local\n\n", print_agent_status(agt_status));
            }else if(json_output){
                cJSON_AddStringToObject(json_data, "id", "000");
                cJSON_AddStringToObject(json_data, "name", shost);
                cJSON_AddStringToObject(json_data, "ip", "127.0.0.1");
                cJSON_AddStringToObject(json_data, "status", print_agent_status(agt_status));
            } else {
                printf("000,%s,127.0.0.1,%s/Local,",
                       shost,
                       print_agent_status(agt_status));
            }
        }

        if (!csv_output && !json_output) {
            printf("   Operating system:    %s\n", agt_info->os);
            printf("   Client version:      %s\n", agt_info->version);
            printf("   Shared file hash:    %s\n", agt_info->merged_sum);
            printf("   Last keep alive:     %s\n\n", agt_info->last_keepalive);

            printf("   Syscheck last started at:  %s\n", agt_info->syscheck_time);
            printf("   Syscheck last ended at:    %s\n", agt_info->syscheck_endtime);

            if (end_time) {
                printf("   Rootcheck last started at: %s\n", agt_info->rootcheck_time);
                printf("   Rootcheck last ended at:   %s\n\n", agt_info->rootcheck_endtime);
            } else {
                printf("   Rootcheck last started at: %s\n", agt_info->rootcheck_time);
            }
        }else if(json_output){
                cJSON_AddStringToObject(json_data, "os", agt_info->os);
                cJSON_AddStringToObject(json_data, "version", agt_info->version);
                cJSON_AddStringToObject(json_data, "mergedSum", agt_info->merged_sum);
                cJSON_AddStringToObject(json_data, "lastKeepAlive", agt_info->last_keepalive);
                cJSON_AddStringToObject(json_data, "syscheckTime", agt_info->syscheck_time);
                cJSON_AddStringToObject(json_data, "syscheckEndTime", agt_info->syscheck_endtime);
                cJSON_AddStringToObject(json_data, "rootcheckTime", agt_info->rootcheck_time);

                if (end_time) {
                    cJSON_AddStringToObject(json_data, "rootcheckEndTime", agt_info->rootcheck_endtime);
                }
        } else {
            printf("%s,%s,%s,%s,%s,\n",
                   agt_info->os,
                   agt_info->version,
                   agt_info->last_keepalive,
                   agt_info->syscheck_time,
                   agt_info->rootcheck_time);
        }
        if(json_output){
            cJSON_AddNumberToObject(root, "error", 0);
            cJSON_AddItemToObject(root, "data", json_data);
            printf("%s",cJSON_PrintUnformatted(root));
            cJSON_Delete(root);
        }
        exit(0);
    }

    /* Restart syscheck everywhere */
    if (restart_all_agents && restart_syscheck) {
        /* Restart agent 000 */
        os_set_restart_syscheck();

        /* Connect to remoted */
        mdebug1("Connecting to remoted...");
        arq = connect_to_remoted();
        if (arq < 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 41);
                cJSON_AddStringToObject(root, "message", "Unable to connect to remoted");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to connect to remoted.\n");
            }
            exit(1);
        }
        mdebug1("Connected...");

        /* Send restart message to all agents */
        if (send_msg_to_agent(arq, HC_SK_RESTART, NULL, NULL) == 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 0);
                cJSON_AddStringToObject(root, "data", "Restarting Syscheck/Rootcheck on all agents");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n%s %s: Restarting Syscheck/Rootcheck on all agents.", __ossec_name, ARGV0);
            }
        } else {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 42);
                cJSON_AddStringToObject(root, "message", "Unable to restart syscheck on all agents");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to restart syscheck on all agents.\n");
            }
            exit(1);
        }

        exit(0);
    }

    if (restart_syscheck && agent_id) {
        /* Restart on the server */
        if (strcmp(agent_id, "000") == 0) {
            os_set_restart_syscheck();
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 0);
                cJSON_AddStringToObject(root, "data", "Restarting Syscheck/Rootcheck locally");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n%s %s: Restarting Syscheck/Rootcheck ""locally.\n", __ossec_name, ARGV0);
            }
            exit(0);
        }

        /* Connect to remoted */
        mdebug1("Connecting to remoted...");
        arq = connect_to_remoted();
        if (arq < 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 43);
                cJSON_AddStringToObject(root, "message", "Unable to connect to remoted");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to connect to remoted.\n");
            }
            exit(1);
        }
        mdebug1("Connected...");

        if (send_msg_to_agent(arq, HC_SK_RESTART, agent_id, NULL) == 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 0);
                cJSON_AddStringToObject(root, "data", "Restarting Syscheck/Rootcheck on agent");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n%s %s: Restarting Syscheck/Rootcheck on agent: %s\n",__ossec_name, ARGV0, agent_id);
            }
        } else {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 44);
                cJSON_AddStringToObject(root, "message", "Unable to restart syscheck on agent");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to restart syscheck on agent: %s\n", agent_id);
            }
            exit(1);
        }

        exit(0);
    }

    if (restart_agent) {
        if (!(agent_id || restart_all_agents)) {
            if (json_output) {
                cJSON_AddNumberToObject(root, "error", 45);
                cJSON_AddStringToObject(root, "message", "Agent not specified");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            } else {
                printf("\n** Agent not specified.\n");
            }

            exit(1);
        }

        /* Connect to remoted */
        mdebug1("Connecting to remoted...");
        arq = connect_to_remoted();
        if (arq < 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 43);
                cJSON_AddStringToObject(root, "message", "Unable to connect to remoted");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to connect to remoted.\n");
            }
            exit(1);
        }
        mdebug1("Connected...");

        if (send_msg_to_agent(arq, "restart-ossec0", restart_all_agents ? NULL : agent_id, "null") == 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 0);
                cJSON_AddStringToObject(root, "data", restart_all_agents ? "Restarting all agents" : "Restarting agent");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            } else {
                printf("\n%s %s: Restarting agent: %s\n", __ossec_name, ARGV0, restart_all_agents ? "(all)" : agent_id);
            }
        } else {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 46);
                cJSON_AddStringToObject(root, "message", "Unable to restart agent");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to restart agent: %s\n", agent_id);
            }
            exit(1);
        }

        exit(0);
    }

    /* Run active response on the specified agent id */
    if (ip_address && ar && (agent_id || restart_all_agents)) {
        /* Connect to remoted */
        FILE *fp;
        int pass = 0;

        if (fp = fopen(DEFAULTAR, "r"), fp) {
            char name[256];
            char command[256];
            unsigned timeout;
            char end;
            int line;
            int r;

            for (line = 1; r = fscanf(fp, "%255s - %255s - %u%c", name, command, &timeout, &end), r == 4; line++) {
                if (strcmp(name, ar) == 0) {
                    pass = 1;
                    break;
                }
            }

            if (r != 4 && r != EOF) {
                printf("\n** Active response file is corrupted at line %d.\n", line);
                exit(EXIT_FAILURE);
            }
        } else {
            printf("\n** Active response is not available.\n");
            exit(EXIT_FAILURE);
        }

        if (!pass) {
            printf("\n** Selected active response does not exist.\n");
            exit(EXIT_FAILURE);
        }

        mdebug1("Connecting to remoted...");
        arq = connect_to_remoted();
        if (arq < 0) {
            printf("\n** Unable to connect to remoted.\n");
            exit(1);
        }
        mdebug1("Connected...");

        if (send_msg_to_agent(arq, ar, agent_id, ip_address) == 0) {
            printf("\n%s %s: Running active response '%s' on: %s\n",
                   __ossec_name, ARGV0, ar, agent_id ? agent_id : "all");
        } else {
            if (json_output) {
                cJSON_AddNumberToObject(root, "error", 47);
                cJSON_AddStringToObject(root, "message", "Unable to run active response");
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            } else if (agent_id) {
                printf("\n** Unable to run active response on all agents.\n");
            } else {
                printf("\n** Unable to run active response on agent: %s\n", agent_id);
            }

            exit(1);
        }

        exit(0);
    }

    printf("\n** Invalid argument combination.\n");
    helpmsg();

    return (0);
}

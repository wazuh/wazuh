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
#include "external/cJSON/cJSON.h"

#undef ARGV0
#define ARGV0 "agent_control"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\nOSSEC HIDS %s: Control remote agents.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-l          List available (active or not) agents.\n");
    printf("\t-lc         List active agents.\n");
    printf("\t-i <id>     Extracts information from an agent.\n");
    printf("\t-R <id>     Restarts agent.\n");
    printf("\t-r -a       Runs the integrity/rootkit checking on all agents now.\n");
    printf("\t-r -u <id>  Runs the integrity/rootkit checking on one agent now.\n\n");
    printf("\t-b <ip>     Blocks the specified ip address.\n");
    printf("\t-f <ar>     Used with -b, specifies which response to run.\n");
    printf("\t-L          List available active responses.\n");
    printf("\t-s          Changes the output to CSV (comma delimited).\n");
	printf("\t-j          Changes the output to JSON .\n");
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

    cJSON *root;
    cJSON *response;

    int arq = 0;
    gid_t gid;
    uid_t uid;
    int c = 0, restart_syscheck = 0, restart_all_agents = 0, list_agents = 0;
    int info_agent = 0, agt_id = 0, active_only = 0, csv_output = 0, json_output = 0;
    int list_responses = 0, end_time = 0, restart_agent = 0;

    char shost[512];

    keystore keys;

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    while ((c = getopt(argc, argv, "VehdlLcsjaru:i:b:f:R:")) != -1) {
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
            /* no break; */
            case 'u':
                if (!optarg) {
                    merror("%s: -u needs an argument", ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                break;
            case 'b':
                if (!optarg) {
                    merror("%s: -b needs an argument", ARGV0);
                    helpmsg();
                }
                ip_address = optarg;
                break;
            case 'f':
                if (!optarg) {
                    merror("%s: -e needs an argument", ARGV0);
                    helpmsg();
                }
                ar = optarg;
                break;
            case 'R':
                if (!optarg) {
                    merror("%s: -R needs an argument", ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                restart_agent = 1;
                break;
            case 'a':
                restart_all_agents = 1;
                break;
            default:
                helpmsg();
                break;
        }

    }

    /* Prepare JSON Structure */
    if(json_output){
        root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "response", response = cJSON_CreateObject());
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

    /* List responses */
    if (list_responses) {
        FILE *fp;
        if (!csv_output && !json_output) {
            printf("\nOSSEC HIDS %s. Available active responses:\n", ARGV0);
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
        if (!csv_output && !json_output) {
            printf("\nOSSEC HIDS %s. List of available agents:",
                   ARGV0);
            printf("\n   ID: 000, Name: %s (server), IP: 127.0.0.1, Active/Local\n",
                   shost);
		} else if(json_output){
				printf("[ { \"ID\" : \"000\", \"Name\" : \"%s (server)\", \"IP\": \"127.0.0.1\", \"Status\" : \"Active/Local\" }",shost);
        } else {
            printf("000,%s (server),127.0.0.1,Active/Local,\n", shost);
        }
        print_agents(1, active_only, csv_output, json_output);
		// Closing JSON Object array
		if(json_output)
			 printf("]");
		else
			printf("\n");
        exit(0);
    }

    /* Check if the provided ID is valid */
    if (agent_id != NULL) {
        if (strcmp(agent_id, "000") != 0) {
            OS_ReadKeys(&keys);

            agt_id = OS_IsAllowedID(&keys, agent_id);
            if (agt_id < 0) {
                if(json_output){
                    cJSON_AddNumberToObject(root, "error", 1); 
                    cJSON_AddStringToObject(root, "description", "Invalid agent id"); 
                    printf("%s",cJSON_PrintUnformatted(root));
                    cJSON_Delete(root);
                    exit(1);
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
        int agt_status = 0;
        char final_ip[128 + 1];
        char final_mask[128 + 1];
        agent_info *agt_info;
        final_ip[128] = '\0';
        final_mask[128] = '\0';

        if (!csv_output && !json_output) {
            printf("\nOSSEC HIDS %s. Agent information:", ARGV0);
        }

        if (agt_id != -1) {
            agt_status = get_agent_status(keys.keyentries[agt_id]->name,
                                          keys.keyentries[agt_id]->ip->ip);

            agt_info = get_agent_info(keys.keyentries[agt_id]->name,
                                      keys.keyentries[agt_id]->ip->ip);

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
                cJSON_AddStringToObject(response, "id", keys.keyentries[agt_id]->id); 
                cJSON_AddStringToObject(response, "name", keys.keyentries[agt_id]->name); 
                cJSON_AddStringToObject(response, "ip", final_ip); 
                cJSON_AddStringToObject(response, "status", print_agent_status(agt_status)); 
            } else {
                printf("%s,%s,%s,%s,",
                       keys.keyentries[agt_id]->id,
                       keys.keyentries[agt_id]->name,
                       final_ip,
                       print_agent_status(agt_status));
            }
        } else {
            agt_status = get_agent_status(NULL, NULL);
            agt_info = get_agent_info(NULL, "127.0.0.1");

            if (!csv_output && !json_output) {
                printf("\n   Agent ID:   000 (local instance)\n");
                printf("   Agent Name: %s\n", shost);
                printf("   IP address: 127.0.0.1\n");
                printf("   Status:     %s/Local\n\n", print_agent_status(agt_status));
            }else if(json_output){  
                cJSON_AddStringToObject(response, "id", "000 (local instance)"); 
                cJSON_AddStringToObject(response, "name", shost); 
                cJSON_AddStringToObject(response, "ip", "127.0.0.1"); 
                cJSON_AddStringToObject(response, "status", print_agent_status(agt_status)); 
            } else {
                printf("000,%s,127.0.0.1,%s/Local,",
                       shost,
                       print_agent_status(agt_status));
            }
        }

        if (!csv_output && !json_output) {
            printf("   Operating system:    %s\n", agt_info->os);
            printf("   Client version:      %s\n", agt_info->version);
            printf("   Last keep alive:     %s\n\n", agt_info->last_keepalive);

            if (end_time) {
                printf("   Syscheck last started at:  %s\n", agt_info->syscheck_time);
                printf("   Syscheck last ended   at:  %s\n", agt_info->syscheck_endtime);
                printf("   Rootcheck last started at: %s\n", agt_info->rootcheck_time);
                printf("   Rootcheck last ended   at: %s\n\n", agt_info->rootcheck_endtime);
            } else {
                printf("   Syscheck last started  at: %s\n", agt_info->syscheck_time);
                printf("   Rootcheck last started at: %s\n", agt_info->rootcheck_time);
            }
        }else if(json_output){  
                cJSON_AddStringToObject(response, "operating_system", agt_info->os); 
                cJSON_AddStringToObject(response, "client_version", agt_info->version); 
                cJSON_AddStringToObject(response, "last_keepalive", agt_info->last_keepalive);
                
                cJSON_AddStringToObject(response, "syscheck_last_started", agt_info->syscheck_time);
                if (end_time)
                    cJSON_AddStringToObject(response, "syscheck_last_ended", agt_info->syscheck_endtime);    

                cJSON_AddStringToObject(response, "rootcheck_last_started", agt_info->rootcheck_time);  
                if (end_time)
                    cJSON_AddStringToObject(response, "rootcheck_last_ended", agt_info->rootcheck_endtime);  
                 
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
            printf("%s",cJSON_PrintUnformatted(root));
            cJSON_Delete(root);
        }
        exit(0);
    }

    /* Restart syscheck everywhere */
    if (restart_all_agents && restart_syscheck) {
        /* Connect to remoted */
        debug1("%s: DEBUG: Connecting to remoted...", ARGV0);
        arq = connect_to_remoted();
        if (arq < 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 1); 
                cJSON_AddStringToObject(root, "description", "Unable to connect to remoted(1)"); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to connect to remoted.\n");
            }
            exit(1);
        }
        debug1("%s: DEBUG: Connected...", ARGV0);

        /* Send restart message to all agents */
        if (send_msg_to_agent(arq, HC_SK_RESTART, NULL, NULL) == 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 0); 
                cJSON_AddStringToObject(root, "description", ""); 
                cJSON_AddStringToObject(response, "message", "Restarting Syscheck/Rootcheck on all agents"); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\nOSSEC HIDS %s: Restarting Syscheck/Rootcheck on all agents.",ARGV0);
            }
        } else {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 1); 
                cJSON_AddStringToObject(root, "description", "Unable to restart syscheck on all agents"); 
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
                cJSON_AddStringToObject(root, "description", ""); 
                cJSON_AddStringToObject(response, "message", "Restarting Syscheck/Rootcheck locally."); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\nOSSEC HIDS %s: Restarting Syscheck/Rootcheck ""locally.\n", ARGV0);
            }
            exit(0);
        }

        /* Connect to remoted */
        debug1("%s: DEBUG: Connecting to remoted...", ARGV0);
        arq = connect_to_remoted();
        if (arq < 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 1); 
                cJSON_AddStringToObject(root, "description", "Unable to connect to remoted(2)"); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to connect to remoted.\n");
            }
            exit(1);
        }
        debug1("%s: DEBUG: Connected...", ARGV0);

        if (send_msg_to_agent(arq, HC_SK_RESTART, agent_id, NULL) == 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 0); 
                cJSON_AddStringToObject(root, "description", ""); 
                cJSON_AddStringToObject(response, "message", "Restarting Syscheck/Rootcheck on agent"); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\nOSSEC HIDS %s: Restarting Syscheck/Rootcheck on agent: %s\n",ARGV0, agent_id);
            }
        } else {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 1); 
                cJSON_AddStringToObject(root, "description", "Unable to restart syscheck on agent"); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to restart syscheck on agent: %s\n", agent_id);
            }
            exit(1);
        }

        exit(0);
    }

    if (restart_agent && agent_id) {

        /* Connect to remoted */
        debug1("%s: DEBUG: Connecting to remoted...", ARGV0);
        arq = connect_to_remoted();
        if (arq < 0) {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 1); 
                cJSON_AddStringToObject(root, "description", "Unable to connect to remoted(3)"); 
                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\n** Unable to connect to remoted.\n");
            }
            exit(1);
        }
        debug1("%s: DEBUG: Connected...", ARGV0);

        if (send_msg_to_agent(arq, "restart-ossec0", agent_id, "null") == 0) {
            if(json_output){
                char final_ip[128 + 1];
                char final_mask[128 + 1];
                final_ip[128] = '\0';
                final_mask[128] = '\0';

                /* Get netmask from IP */
                getNetmask(keys.keyentries[agt_id]->ip->netmask, final_mask, 128);
                snprintf(final_ip, 128, "%s%s", keys.keyentries[agt_id]->ip->ip,final_mask);

                cJSON_AddStringToObject(response, "id", keys.keyentries[agt_id]->id); 
                cJSON_AddStringToObject(response, "name", keys.keyentries[agt_id]->name); 
                cJSON_AddStringToObject(response, "ip", final_ip); 

                cJSON_AddNumberToObject(root, "error", 0); 
                cJSON_AddStringToObject(root, "description", ""); 
                cJSON_AddStringToObject(response, "message", "Restarting agent"); 

                printf("%s",cJSON_PrintUnformatted(root));
                cJSON_Delete(root);
            }else{
                printf("\nOSSEC HIDS %s: Restarting agent: %s\n",ARGV0, agent_id);
            }
        } else {
            if(json_output){
                cJSON_AddNumberToObject(root, "error", 1); 
                cJSON_AddStringToObject(root, "description", "Unable to restart agent"); 
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
    if (ip_address && ar && agent_id) {
        /* Connect to remoted */
        debug1("%s: DEBUG: Connecting to remoted...", ARGV0);
        arq = connect_to_remoted();
        if (arq < 0) {
            printf("\n** Unable to connect to remoted.\n");
            exit(1);
        }
        debug1("%s: DEBUG: Connected...", ARGV0);

        if (send_msg_to_agent(arq, ar, agent_id, ip_address) == 0) {
            printf("\nOSSEC HIDS %s: Running active response '%s' on: %s\n",
                   ARGV0, ar, agent_id);
        } else {
            printf("\n** Unable to restart syscheck on agent: %s\n", agent_id);
            exit(1);
        }

        exit(0);
    }

    printf("\n** Invalid argument combination.\n");
    helpmsg();

    return (0);
}


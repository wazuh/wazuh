/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"
#include "read-agents.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"

static int mon_send_agent_msg(char *agent, char *msg);
static bool validate_single_filter(cJSON *j_agent_info, char** filter_listm, char *field_to_validate);
static bool validate_filters(cJSON *j_agent_info, monitor_delete_agents_filters* current_filters);
int sock = -1;

void monitor_send_deletion_msg(char *agent) {
    char str[OS_SIZE_1024];

    memset(str, '\0', OS_SIZE_1024);
    snprintf(str, OS_SIZE_1024, OS_AG_REMOVED, agent);

    if (SendMSG(mond.a_queue, str, ARGV0, LOCALFILE_MQ) < 0) {
        mond.a_queue = -1;  // set an invalid fd so we can attempt to reconnect later on.
        mdebug1("Could not generate removed agent alert for '%s'", agent);
        merror(QUEUE_SEND);
    }
}

void monitor_send_disconnection_msg(char *agent) {
    char str[OS_SIZE_1024];
    int error;

    memset(str, '\0', OS_SIZE_1024);
    /* Send disconnected message */
    snprintf(str, OS_SIZE_1024, AG_DISCON_MSG, agent);
    if (error = mon_send_agent_msg(agent, str), error) {
        if (error == 2) {
            // Agent is no longer in the database
            monitor_send_deletion_msg(agent);
        } else {
            mdebug1("Could not generate disconnected agent alert for '%s'", agent);
        }
    }
}

void monitor_agents_disconnection(){
    int *agents_array;
    char str_agent_id[12];

    //The master will disconnect and alert the agents on its own DB. Thus, synchronization is not required.
    agents_array = wdb_disconnect_agents(time(0) - mond.global.agents_disconnection_time,
                                         "synced", &sock);
    if (mond.monitor_agents != 0 && agents_array) {
        for (int i = 0; agents_array[i] != -1; i++) {
            snprintf(str_agent_id, 12, "%d", agents_array[i]);
            if (OSHash_Add(agents_to_alert_hash, str_agent_id, (void*)time(0)) == 0) {
                mdebug1("Can't add agent ID '%d' to the alerts hash table", agents_array[i]);
            }
        }
    }
    os_free(agents_array);
}

void monitor_agents_alert(){
    unsigned int inode_it = 0;
    OSHashNode *agent_hash_node = NULL;
    OSHashNode *agent_hash_next_node = NULL;

    cJSON *j_agent_info = NULL;
    cJSON *j_agent_status = NULL;
    cJSON *j_agent_lastkeepalive = NULL;
    cJSON *j_agent_name = NULL;
    cJSON *j_agent_ip = NULL;

    agent_hash_node = OSHash_Begin(agents_to_alert_hash, &inode_it);
    while (agent_hash_node) {
        agent_hash_next_node = OSHash_Next(agents_to_alert_hash, &inode_it, agent_hash_node);

        j_agent_info = wdb_get_agent_info(atoi(agent_hash_node->key), &sock);
        if (j_agent_info) {
            j_agent_status = cJSON_GetObjectItem(j_agent_info->child, "connection_status");
            j_agent_lastkeepalive = cJSON_GetObjectItem(j_agent_info->child, "last_keepalive");
            j_agent_name = cJSON_GetObjectItem(j_agent_info->child, "name");
            j_agent_ip = cJSON_GetObjectItem(j_agent_info->child, "register_ip");

            if (cJSON_IsString(j_agent_status) && j_agent_status->valuestring != NULL &&
                cJSON_IsString(j_agent_name) && j_agent_name->valuestring != NULL &&
                cJSON_IsString(j_agent_ip) && j_agent_ip->valuestring != NULL &&
                cJSON_IsNumber(j_agent_lastkeepalive)) {

                    if (strcmp(j_agent_status->valuestring, "active") == 0) {
                        /* The agent is now connected, removing from table */
                        OSHash_Delete(agents_to_alert_hash, agent_hash_node->key);
                    }

                    else if (j_agent_lastkeepalive->valueint < (time(0) -
                            (mond.global.agents_disconnection_time + mond.global.agents_disconnection_alert_time))) {
                        /* Generating the disconnection alert */
                        char *agent_name_ip = NULL;
                        os_strdup(j_agent_name->valuestring, agent_name_ip);
                        wm_strcat(&agent_name_ip, j_agent_ip->valuestring, '-');
                        monitor_send_disconnection_msg(agent_name_ip);
                        OSHash_Delete(agents_to_alert_hash, agent_hash_node->key);
                        os_free(agent_name_ip);
                    }
                }
        } else {
            mdebug1("Unable to retrieve agent's '%s' data from Wazuh DB", agent_hash_node->key);
            OSHash_Delete(agents_to_alert_hash, agent_hash_node->key);
        }
        cJSON_Delete(j_agent_info);
        agent_hash_node = agent_hash_next_node;
    }
}

void monitor_agents_deletion(void) {
    int *agents_array[5] = {0};
    monitor_delete_agents_filters* next_filters = NULL;
    monitor_delete_agents_filters* current_filters = mond.delete_agents.filters;

    while (current_filters != NULL) {
        next_filters = current_filters->next;

        if (current_filters->status_list) {
            for (unsigned int i = 0; current_filters->status_list[i] != 0; i++) {
                agents_array[i] = wdb_get_agents_by_connection_status(current_filters->status_list[i], &sock);
            }
        }

        for (unsigned int i = 0; agents_array[i] != 0; i++) {
            for (unsigned int j = 0; agents_array[i][j] != -1; j++) {
                const int agent_id = agents_array[i][j];
                cJSON *j_agent_info = wdb_get_agent_info(agent_id, &sock);

                if (j_agent_info) {

                    cJSON *j_agent_status = cJSON_GetObjectItem(j_agent_info->child, "connection_status");

                    if (cJSON_IsString(j_agent_status) && j_agent_status->valuestring != NULL) {

                        int should_delete_agent = 0;

                        if (strcmp(j_agent_status->valuestring, AGENT_DELETE_STATUS_NEVER_CONNECTED) == 0) {
                            cJSON *j_agent_reg_time = cJSON_GetObjectItem(j_agent_info->child, "date_add");

                            if(cJSON_IsNumber(j_agent_reg_time)) {
                                should_delete_agent = (long int) difftime(time(0), j_agent_reg_time->valueint) > current_filters->older_than ? 1 : 0;
                            }
                        }
                        else {
                            cJSON *j_agent_lastkeepalive = cJSON_GetObjectItem(j_agent_info->child, "last_keepalive");

                            if (cJSON_IsNumber(j_agent_lastkeepalive)) {
                                should_delete_agent = (long int) difftime(time(0), j_agent_lastkeepalive->valueint) > current_filters->older_than ? 1 : 0;
                            }
                        }
                        if (should_delete_agent) {
                            if (validate_filters(j_agent_info, current_filters) && (0 == delete_old_agent(agent_id))) {
                                cJSON *j_agent_name = cJSON_GetObjectItem(j_agent_info->child, "name");
                                cJSON *j_agent_ip = cJSON_GetObjectItem(j_agent_info->child, "register_ip");

                                if (cJSON_IsString(j_agent_name) && j_agent_name->valuestring !=0 &&
                                        cJSON_IsString(j_agent_ip) && j_agent_ip->valuestring !=0) {
                                    char *agent_name_ip = NULL;

                                    os_strdup(j_agent_name->valuestring, agent_name_ip);
                                    wm_strcat(&agent_name_ip, j_agent_ip->valuestring, '-');
                                    monitor_send_deletion_msg(agent_name_ip);
                                    os_free(agent_name_ip);
                                }
                            }
                        }
                        cJSON_Delete(j_agent_info);
                    }
                }
                else {
                    char str_agent_id[12];
                    mdebug1("Unable to retrieve agent's '%d' data from Wazuh DB", agent_id);
                    snprintf(str_agent_id, 12, "%d", agent_id);
                    OSHash_Delete(agents_to_alert_hash, str_agent_id);
                }
            }
            os_free(agents_array[i]);
            agents_array[i] = 0;
        }
        current_filters = next_filters;
    }
}

static bool validate_single_filter(cJSON *j_agent_info, char** filter_listm, char *field_to_validate) {
    cJSON *j_agent_field = cJSON_GetObjectItem(j_agent_info->child, field_to_validate);

    if (cJSON_IsString(j_agent_field) && j_agent_field != 0) {
        for (int os_indx = 0; filter_listm[os_indx] != 0; ++os_indx) {
            if (strcmp(field_to_validate, "group") == 0){
                char* token = strtok(j_agent_field->valuestring, ",");
                int i = 0;
                for(; token != 0; ++i) {
                    if (strcmp(filter_listm[os_indx], token) == 0) {
                        return true;
                    }
                    token = strtok(NULL, ",");
                }
            } else {
                if (strcmp(filter_listm[os_indx], j_agent_field->valuestring) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

static bool validate_filters(cJSON *j_agent_info, monitor_delete_agents_filters* current_filters) {
    if (current_filters->os_name_list && validate_single_filter(j_agent_info, current_filters->os_name_list, "os_name") == false) {
        return false;
    }
    if (current_filters->os_platform_list && validate_single_filter(j_agent_info, current_filters->os_platform_list, "os_platform") == false) {
        return false;
    }
    if (current_filters->os_version_list && validate_single_filter(j_agent_info, current_filters->os_version_list, "os_version") == false) {
        return false;
    }
    if (current_filters->version_list && validate_single_filter(j_agent_info, current_filters->version_list, "version") == false) {
        return false;
    }
    if (current_filters->group_list && validate_single_filter(j_agent_info, current_filters->group_list, "group") == false) {
        return false;
    }

    return true;
}

void monitor_logs(bool check_logs_size, char path[PATH_MAX], char path_json[PATH_MAX]) {
    struct stat buf;
    off_t size;

    if (check_logs_size == FALSE && mond.rotate_log) {
        sleep(mond.day_wait);
        /* Daily rotation and compression of ossec.log/ossec.json */
        w_rotate_log(mond.compress, mond.keep_log_days, 1, 0, mond.daily_rotations);

    } else if (check_logs_size == TRUE && mond.rotate_log && mond.size_rotate > 0){
        if (stat(path, &buf) == 0) {
            size = buf.st_size;
            /* If log file reachs maximum size, rotate ossec.log */
            if ( (unsigned long) size >= mond.size_rotate) {
                w_rotate_log(mond.compress, mond.keep_log_days, 0, 0, mond.daily_rotations);
            }
        }

        if (stat(path_json, &buf) == 0) {
            size = buf.st_size;
            /* If log file reachs maximum size, rotate ossec.json */
            if ( (unsigned long) size >= mond.size_rotate) {
                w_rotate_log(mond.compress, mond.keep_log_days, 0, 1, mond.daily_rotations);
            }
        }
    }
}

int delete_old_agent(int agent_id) {
    int val = -1;
    char agent_id_str[16] = {0};
    if(snprintf(agent_id_str, 16, "%03d", agent_id)) {
        int sock;
        if (sock = auth_connect(), sock < 0) {
            mdebug1("Monitord could not connect to to Authd socket. Is Authd running?");
        }
        else {
            int json_output = 1;
            val = auth_remove_agent(sock, agent_id_str, json_output);
            auth_close(sock);
        }
    }
    return val;
}

int mon_send_agent_msg(char *agent, char *msg) {
    char header[OS_SIZE_256];
    char ag_name[OS_SIZE_128];
    int ag_id;
    char *ag_ip = NULL;
    char *found = agent;
    size_t name_size;

    while (found = strchr(found, '-'), found) {
        ag_ip = ++found;
    }

    if (!ag_ip) {
        return 1;
    }

    if (name_size = strlen(agent) - strlen(ag_ip), name_size > OS_SIZE_128) {
        return 1;
    }

    snprintf(ag_name, name_size, "%s", agent);

    if (ag_id = wdb_find_agent(ag_name, ag_ip, NULL), ag_id > 0) {

        snprintf(header, OS_SIZE_256, "[%03d] (%s) %s", ag_id, ag_name, ag_ip);
        if (SendMSG(mond.a_queue, msg, header, SECURE_MQ) < 0) {
            mond.a_queue = -1;  // set an invalid fd so we can attempt to reconnect later on.
            merror(QUEUE_SEND);
            return 1;
        }
        return 0;
    } else if (ag_id == -2) {
        return 2;
    }

    return 1;
}

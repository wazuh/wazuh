/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Manage agents tool
 * Add/extract and remove agents from a server
 */

#include "manage_agents.h"
#include "debug_op.h"
#include "defs.h"
#include "os_crypto/md5/md5_op.h"
#include "external/cJSON/cJSON.h"
#include "os_err.h"
#include <stdio.h>
#include <stdlib.h>
#include "config/authd-config.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuh_db/wdb.h"

#if defined(__hppa__)
static int setenv(const char *name, const char *val, __attribute__((unused)) int overwrite)
{
    int len = strlen(name) + strlen(val) + 2;
    char *str = (char *)malloc(len);
    snprintf(str, len, "%s=%s", name, val);
    putenv(str);
    return 0;
}
#endif

/* Global variables */
time_t time1;
time_t time2;
time_t time3;
long int rand1;
long int rand2;

/* Remove spaces, newlines, etc from a string */
char *chomp(char *str)
{
    char *tmp_str;
    ssize_t size;

    /* Remove spaces from the beginning */
    while (*str == ' ' || *str == '\t') {
        str++;
    }

    /* Remove any trailing newlines or \r */
    do {
        tmp_str = strchr(str, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
            continue;
        }

        tmp_str = strchr(str, '\r');
        if (tmp_str) {
            *tmp_str = '\0';
        }
    } while (tmp_str != NULL);

    /* Remove spaces at the end of the string */
    tmp_str = str;
    size = (ssize_t) strlen(str) - 1;

    while ((size >= 0) && (tmp_str[size] == ' ' || tmp_str[size] == '\t')) {
        tmp_str[size] = '\0';
        size--;
    }

    return (str);
}

#ifndef CLIENT

int add_agent(int json_output)
{
    int i = 1;
    FILE *fp;
    File file;
    char str1[STR_SIZE + 1];
    char str2[STR_SIZE + 1];

    os_md5 md1;
    os_md5 md2;
    char key[65];

    char *user_input;
    char *_name;
    char *_id;
    char *_ip;

    char name[FILE_SIZE + 1];
    char id[FILE_SIZE + 1] = { '\0' };
    char ip[FILE_SIZE + 1];

    char *id_exist = NULL;
    authd_force_options_t authd_force_options = {0};
    int sock;
    int authd_running;

    // Creating the configuration structure according to the parameters used
    const char *env_disconnected_time = getenv("DISCONNECTED_TIME");

    if (env_disconnected_time) {
        authd_force_options.disconnected_time = strtol(env_disconnected_time, NULL, 10);
        authd_force_options.disconnected_time_enabled = true;
        authd_force_options.enabled = true;
    }

    const char *env_after_registration_time = getenv("AFTER_REGISTRATION_TIME");

    if (env_after_registration_time) {
        authd_force_options.after_registration_time = strtol(env_after_registration_time, NULL, 10);
        authd_force_options.enabled = true;
    }

    // Create socket

    if (sock = auth_connect(), sock < 0) {
        authd_running = 0;
        /* Check if we can open the auth_file */
        fp = wfopen(KEYS_FILE, "a");
        if (!fp) {
            if (json_output) {
                char buffer[1024];
                cJSON *json_root = cJSON_CreateObject();
                snprintf(buffer, 1023, "Could not open file '%s' due to [(%d)-(%s)]", KEYS_FILE, errno, strerror(errno));
                cJSON_AddNumberToObject(json_root, "error", 71);
                cJSON_AddStringToObject(json_root, "message", buffer);
                printf("%s", cJSON_PrintUnformatted(json_root));
                exit(1);
            } else
                merror_exit(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
        }
        fclose(fp);

        /* Set time 2 */
        time2 = time(0);
        rand1 = os_random();
    } else {
        authd_running = 1;
        close(sock);
        sock = -1;
    }

    if (!json_output)
        printf(ADD_NEW);

    do {
        if (!json_output) {
            printf(ADD_NAME);
            fflush(stdout);
        }
        /* Read the agent's name from user environment. If it is invalid
         * we should force user to provide a name from input device.
         */
        _name = getenv("OSSEC_AGENT_NAME");
        if (_name == NULL || !strcmp(_name, shost) || NameExist(_name) || !OS_IsValidName(_name)) {
            if (json_output) {
                cJSON *json_root = cJSON_CreateObject();

                if (_name && (!strcmp(_name, shost) || NameExist(_name))) {
                    cJSON_AddNumberToObject(json_root, "error", 75);
                    cJSON_AddStringToObject(json_root, "message", "Name already present");
                } else {
                    cJSON_AddNumberToObject(json_root, "error", 76);
                    cJSON_AddStringToObject(json_root, "message", "Invalid name for agent");
                }

                printf("%s", cJSON_PrintUnformatted(json_root));
                exit(1);
            } else
                _name = read_from_user();
        }

        if (strcmp(_name, QUIT) == 0) {
            goto cleanup;
        }

        strncpy(name, _name, FILE_SIZE - 1);

        /* Check the name */
        if (!OS_IsValidName(name)) {
            printf(INVALID_NAME, name);
        }

        /* Search for name  -- no duplicates (only if Authd is not running) */
        if (!authd_running && (!strcmp(name, shost) || NameExist(name))) {
            printf(ADD_ERROR_NAME, name);
        }
    } while ((!authd_running && (!strcmp(name, shost) || NameExist(name))) || !OS_IsValidName(name));

    /* Get IP */
    memset(ip, '\0', FILE_SIZE + 1);

    do {
        if (!json_output) {
            printf(ADD_IP);
            fflush(stdout);
        }

        /* Read IP address from user's environment. If that IP is invalid,
         * force user to provide IP from input device */
        _ip = getenv("OSSEC_AGENT_IP");

        os_ip *aux_ip;
        os_calloc(1, sizeof(os_ip), aux_ip);

        if (_ip == NULL || !OS_IsValidIP(_ip, aux_ip)) {
            if (json_output) {
                cJSON *json_root = cJSON_CreateObject();
                cJSON_AddNumberToObject(json_root, "error", 77);
                cJSON_AddStringToObject(json_root, "message", "Invalid IP for agent");
                printf("%s", cJSON_PrintUnformatted(json_root));
                w_free_os_ip(aux_ip);
                exit(1);
            } else {
                _ip = read_from_user();
                /* Quit */
                if (strcmp(_ip, QUIT) == 0) {
                    w_free_os_ip(aux_ip);
                    goto cleanup;
                }
                os_free(aux_ip->ip);
                if (!OS_IsValidIP(_ip, aux_ip)) {
                    printf(IP_ERROR, _ip);
                    w_free_os_ip(aux_ip);
                    _ip = NULL;
                    continue;
                }
            }
        }

        strncpy(ip, aux_ip->ip, FILE_SIZE - 1);
        w_free_os_ip(aux_ip);

        if (!authd_running && (id_exist = IPExist(ip))) {
            bool replace_agent = true;
            char error_message[OS_SIZE_128];
            cJSON *j_agent_info = NULL;
            cJSON *j_connection_status = NULL;
            cJSON *j_disconnection_time = NULL;
            cJSON *j_date_add = NULL;

            snprintf(error_message, OS_SIZE_128, "Agent '%s' won't be removed because the force option is disabled.", id_exist);

            j_agent_info = wdb_get_agent_info(atoi(id_exist), NULL);
            if(j_agent_info){
                j_connection_status = cJSON_GetObjectItem(j_agent_info->child, "connection_status");
                j_disconnection_time = cJSON_GetObjectItem(j_agent_info->child, "disconnection_time");
                j_date_add = cJSON_GetObjectItem(j_agent_info->child, "date_add");
            }

            if (!j_agent_info || !j_connection_status || !j_disconnection_time || !j_date_add){
                cJSON_Delete(j_agent_info);
                merror_exit("Failed to get agent-info for agent '%s'", id_exist);
            }

            if(authd_force_options.enabled == false) {
                replace_agent = false;
            } else {
                /* Check if the agent has been disconnected longer than the value required*/
                if (env_disconnected_time) {
                    time_t agent_time_since_desconnection = 0;
                    char *status = j_connection_status->valuestring;

                    if(!strcmp(status, AGENT_CS_DISCONNECTED)) {
                        agent_time_since_desconnection = difftime(time(NULL), j_disconnection_time->valueint);
                        if(agent_time_since_desconnection <= authd_force_options.disconnected_time){
                            replace_agent = false;
                            snprintf(error_message, OS_SIZE_128, "Agent '%s' has not been disconnected long enough to be replaced.", id_exist);
                        }
                    } else if(strcmp(status, AGENT_CS_NEVER_CONNECTED)){
                        replace_agent = false;
                        snprintf(error_message, OS_SIZE_128, "Agent '%s' can't be replaced since it is not disconnected.", id_exist);
                    }
                }

                /* Check if the agent is old enough to be removed */
                if(env_after_registration_time) {
                    if (authd_force_options.after_registration_time != 0){
                        time_t agent_registration_time = difftime(time(NULL), j_date_add->valueint);

                        if(agent_registration_time <= authd_force_options.after_registration_time){
                            snprintf(error_message, OS_SIZE_128, "Agent '%s' has not been registered long enough to be removed.", id_exist);
                            replace_agent = false;
                        }
                    }
                }
            }

            cJSON_Delete(j_agent_info);

            if (replace_agent) {
                OS_RemoveAgent(id_exist);
            } else {
                if (json_output) {
                    cJSON *json_root = cJSON_CreateObject();
                    cJSON_AddNumberToObject(json_root, "error", 79);
                    cJSON_AddStringToObject(json_root, "message", "Duplicate IP for agent");
                    printf("%s", cJSON_PrintUnformatted(json_root));
                    exit(1);
                } else {
                    printf("%s\n", error_message);
                    setenv("OSSEC_AGENT_IP", "", 1);
                    _ip = NULL;
                }
            }

            free(id_exist);
        }
    } while (!_ip);

    if (!authd_running && !*id) {
        do {
            /* Default ID */
            for (i = 1; snprintf(id, sizeof(id), "%03d", i), IDExist(id, 0); i++);

            /* Get ID */

            if (!json_output) {
                printf(ADD_ID, id);
                fflush(stdout);
            }

            /* Get Agent ID from environment. If 0, use default ID. If null,
             * get from user input. If value from environment is invalid,
             * we force user to specify an ID from the terminal. Otherwise,
             * our program goes to infinite loop.
             */
            _id = getenv("OSSEC_AGENT_ID");
            if (_id == NULL || IDExist(_id, 0) || !OS_IsValidID(_id)) {
                _id = read_from_user();
            }

            /* Quit */
            if (strcmp(_id, QUIT) == 0) {
                goto cleanup;
            }

            if (_id[0] != '\0' && strcmp(_id, "0")) {
                strncpy(id, _id, FILE_SIZE - 1);
            }

            if (OS_IsValidID(id)) {
                FormatID(id);
            } else
                printf(INVALID_ID, id);

            /* Search for ID KEY  -- no duplicates */
            if (!authd_running && IDExist(id, 0)) {
                printf(ADD_ERROR_ID, id);
            }
        } while (IDExist(id, 0) || !OS_IsValidID(id));
    }

    if (!authd_running && !json_output) {
        printf(AGENT_INFO, id, name, ip);
        fflush(stdout);
    }

    do {
        if (!json_output)
            printf(ADD_CONFIRM);

        /* Confirmation by an environment variable. The valid value is y/Y.
         * If the user provides anything other string, it is considered as
         * n/N; please note that the old code only accepts y/Y/n/N. So if
         * the variable OSSEC_ACTION_CONFIRMED is 'foobar', the program will
         * go into an infinite loop.
         */
        user_input = getenv("OSSEC_ACTION_CONFIRMED");

        if (user_input == NULL) {
            user_input = read_from_user();
        }

        /* If user accepts to add */
        if (user_input[0] == 'y' || user_input[0] == 'Y') {
            if (!authd_running) {
                time3 = time(0);
                rand2 = os_random();

                if (TempFile(&file, KEYS_FILE, 1) < 0 ) {
                    if (json_output) {
                        char buffer[1024];
                        cJSON *json_root = cJSON_CreateObject();
                        snprintf(buffer, 1023, "Could not open file '%s' due to [(%d)-(%s)]", KEYS_FILE, errno, strerror(errno));
                        cJSON_AddNumberToObject(json_root, "error", 71);
                        cJSON_AddStringToObject(json_root, "message", buffer);
                        printf("%s", cJSON_PrintUnformatted(json_root));
                        exit(1);
                    } else
                        merror_exit(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
                }

                /* Random 1: Time took to write the agent information
                 * Random 2: Time took to choose the action
                 * Random 3: All of this + time + pid
                 * Random 4: Md5 all of this + the name, key and IP
                 * Random 5: Final key
                 */

                os_snprintf(str1, STR_SIZE, "%d%s%d", (int)(time3 - time2), name, (int)rand1);
                os_snprintf(str2, STR_SIZE, "%d%s%s%d", (int)(time2 - time1), ip, id, (int)rand2);

                OS_MD5_Str(str1, -1, md1);
                OS_MD5_Str(str2, -1, md2);

                snprintf(str1, STR_SIZE, "%s%d%d%d", md1, (int)getpid(), os_random(),
                         (int)time3);
                OS_MD5_Str(str1, -1, md1);

                snprintf(key, 65, "%s%s", md1, md2);
                fprintf(file.fp, "%s %s %s %s\n", id, name, ip, key);
                fclose(file.fp);

                if (OS_MoveFile(file.name, KEYS_FILE) < 0) {
                    if (json_output) {
                        char buffer[1024];
                        cJSON *json_root = cJSON_CreateObject();
                        snprintf(buffer, 1023, "Could not write file '%s'", KEYS_FILE);
                        cJSON_AddNumberToObject(json_root, "error", 71);
                        cJSON_AddStringToObject(json_root, "message", buffer);
                        printf("%s", cJSON_PrintUnformatted(json_root));
                        exit(1);
                    } else
                        merror_exit("Could not write file '%s'", KEYS_FILE);
                }

                free(file.name);
                OS_AddAgentTimestamp(id, name, ip, time3);
            } else {
                if (sock = auth_connect(), sock < 0) {
                    if (json_output) {
                        cJSON *json_root = cJSON_CreateObject();
                        cJSON_AddNumberToObject(json_root, "error", 80);
                        cJSON_AddStringToObject(json_root, "message", "Lost authd socket connection.");
                        printf("%s", cJSON_PrintUnformatted(json_root));
                        exit(1);
                    } else
                        merror_exit("Lost authd socket connection.");
                }
                if (w_request_agent_add_local(sock, id, name, ip, NULL, NULL, &authd_force_options, json_output, NULL, 1) < 0) {
                    break;
                }
            }

            if (json_output) {
                cJSON *json_root = cJSON_CreateObject();
                cJSON *json_data = cJSON_CreateObject();
                cJSON_AddStringToObject(json_data, "id", id);
                cJSON_AddStringToObject(json_data, "message", "Agent added");
                cJSON_AddNumberToObject(json_root, "error", 0);
                cJSON_AddItemToObject(json_root, "data", json_data);
                printf("%s", cJSON_PrintUnformatted(json_root));
            } else
                printf(AGENT_ADD, id);

            break;
        } else { /* if(user_input[0] == 'n' || user_input[0] == 'N') */
            printf(ADD_NOT);
            break;
        }
    } while (1);

cleanup:
    auth_close(sock);
    return (0);
}

int remove_agent(int json_output)
{
    char *user_input;
    char u_id[FILE_SIZE + 1];
    int id_exist;
    int sock;
    int authd_running;

    u_id[FILE_SIZE] = '\0';

    if (!(json_output || print_agents(0, 0, 0, 0, 0))) {
        printf(NO_AGENT);
        return (0);
    }

    // Create socket

    if (sock = auth_connect(), sock < 0) {
        authd_running = 0;
    } else {
        auth_close(sock);
        authd_running = 1;
        sock = -1;
    }

    do {
        if (!json_output) {
            printf(REMOVE_ID);
            fflush(stdout);
        }

        user_input = getenv("OSSEC_AGENT_ID");
        if (user_input == NULL) {
            user_input = read_from_user();
        } else if (!json_output) {
            printf("%s\n", user_input);
        }

        if (strcmp(user_input, QUIT) == 0) {
            goto cleanup;
        }

        FormatID(user_input);
        strncpy(u_id, user_input, FILE_SIZE);

        if (!authd_running) {
            if (id_exist = IDExist(user_input, 0), !id_exist) {
                if (json_output) {
                    char buffer[1024];
                    cJSON *json_root = cJSON_CreateObject();
                    snprintf(buffer, 1023, "Invalid ID '%s' given. ID is not present", user_input);
                    cJSON_AddNumberToObject(json_root, "error", 78);
                    cJSON_AddStringToObject(json_root, "message", buffer);
                    printf("%s", cJSON_PrintUnformatted(json_root));
                    exit(1);
                } else
                    printf(NO_ID, user_input);

                /* Exit here if we are using environment variables
                 * and our ID does not exist
                 */
                if (getenv("OSSEC_AGENT_ID")) {
                    exit(1);
                }
            }
        }
    } while (!authd_running && !id_exist);

    do {
        if (!json_output) {
            printf(REMOVE_CONFIRM);
            fflush(stdout);
        }

        user_input = getenv("OSSEC_ACTION_CONFIRMED");
        if (user_input == NULL) {
            user_input = read_from_user();
        } else if (!json_output) {
            printf("%s\n", user_input);
        }

        /* If user confirms */
        if (user_input[0] == 'y' || user_input[0] == 'Y') {
            if (!authd_running) {
                if (!OS_RemoveAgent(u_id)) {
                    if (json_output) {
                        char buffer[1024];
                        cJSON *json_root = cJSON_CreateObject();
                        snprintf(buffer, 1023, "Could not open object '%s' due to [(%d)-(%s)]", KEYS_FILE, errno, strerror(errno));
                        cJSON_AddNumberToObject(json_root, "error", 71);
                        cJSON_AddStringToObject(json_root, "message", buffer);
                        printf("%s", cJSON_PrintUnformatted(json_root));
                        exit(1);
                    } else
                        merror_exit(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
                }
            } else {
                if (sock = auth_connect(), sock < 0) {
                    if (json_output) {
                        cJSON *json_root = cJSON_CreateObject();
                        cJSON_AddNumberToObject(json_root, "error", 80);
                        cJSON_AddStringToObject(json_root, "message", "Lost authd socket connection.");
                        printf("%s", cJSON_PrintUnformatted(json_root));
                        exit(1);
                    } else
                        merror_exit("Lost authd socket connection.");
                }
                if (auth_remove_agent(sock, u_id, json_output) < 0) {
                    break;
                }
            }

            if (json_output) {
                cJSON *json_root = cJSON_CreateObject();
                cJSON_AddNumberToObject(json_root, "error", 0);
                cJSON_AddStringToObject(json_root, "data", "Agent removed");
                printf("%s", cJSON_PrintUnformatted(json_root));
            } else {
                printf(REMOVE_DONE, u_id);
            }

            break;
        } else { /* if(user_input[0] == 'n' || user_input[0] == 'N') */
            printf(REMOVE_NOT);
            break;
        }
    } while (1);

cleanup:
    auth_close(sock);
    return 0;
}

#endif

int list_agents(int cmdlist)
{
    if (!print_agents(0, 0, 0, 0, 0)) {
        printf(NO_AGENT);
    }

    printf("\n");
    if (!cmdlist) {
        printf(PRESS_ENTER);
        read_from_user();
    }

    return (0);
}

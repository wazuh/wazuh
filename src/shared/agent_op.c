/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cJSON.h"
#include "shared.h"
#include "os_crypto/sha256/sha256_op.h"
#include "../os_net/os_net.h"
#include "../addagent/validate.h"
#include "config/authd-config.h"
#include "os_auth/auth.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

static pthread_mutex_t restart_mutex = PTHREAD_MUTEX_INITIALIZER;
/// Pending restart bit field
static struct {
    unsigned syscheck:1;
    unsigned rootcheck:1;
} os_restart;

#ifndef WIN32

//Alloc and create an agent removal command payload
static cJSON* w_create_agent_remove_payload(const char *id, const int purge);

//Parse an agent removal response
static int w_parse_agent_remove_response(const char* buffer,
                                         char *err_response,
                                         const int json_format,
                                         const int exit_on_error);
#endif

//Parse an agent addition response
static int w_parse_agent_add_response(const char* buffer,
                                      char *err_response,
                                      char* id,
                                      char* key,
                                      const int json_format,
                                      const int exit_on_error);

//Alloc and create an agent addition command payload
static cJSON* w_create_agent_add_payload(const char *name,
                                         const char *ip,
                                         const char *groups,
                                         const char *key_hash,
                                         const char *key,
                                         const char *id,
                                         authd_force_options_t *force_options);


/* Check if syscheck is to be executed/restarted
 * Returns 1 on success or 0 on failure (shouldn't be executed now)
 */
int os_check_restart_syscheck()
{
    w_mutex_lock(&restart_mutex);
    int current = os_restart.syscheck;
    os_restart.syscheck = 0;
    w_mutex_unlock(&restart_mutex);
    return current;
}

/* Check if rootcheck is to be executed/restarted
 * Returns 1 on success or 0 on failure (shouldn't be executed now)
 */
int os_check_restart_rootcheck()
{
    w_mutex_lock(&restart_mutex);
    int current = os_restart.rootcheck;
    os_restart.rootcheck = 0;
    w_mutex_unlock(&restart_mutex);
    return current;
}

/* Set syscheck and rootcheck to be restarted */
void os_set_restart_syscheck()
{
    w_mutex_lock(&restart_mutex);
    os_restart.syscheck = 1;
    os_restart.rootcheck = 1;
    w_mutex_unlock(&restart_mutex);
}

/* Read the agent name for the current agent
 * Returns NULL on error
 */
char *os_read_agent_name()
{
    char buf[1024 + 1];
    FILE *fp = NULL;

    mdebug2("Calling os_read_agent_name().");

    fp = wfopen(AGENT_INFO_FILE, "r");

    /* We give 1 second for the file to be created */
    if (!fp) {
        sleep(1);
        fp = wfopen(AGENT_INFO_FILE, "r");
    }

    if (!fp) {
        mdebug1(FOPEN_ERROR, AGENT_INFO_FILE, errno, strerror(errno));
        return (NULL);
    }

    buf[1024] = '\0';

    /* Get name */
    if (fgets(buf, 1024, fp)) {
        char *ret = NULL;
        int len;

        // strip the newlines
        len = strlen(buf) - 1;
        while (len > 0 && buf[len] == '\n')
            buf[len--] = '\0';

        os_strdup(buf, ret);
        fclose(fp);

        mdebug2("os_read_agent_name returned (%s).", ret);

        return (ret);
    }

    fclose(fp);
    return (NULL);
}

/* Read the agent ip for the current agent
 * Returns NULL on error
 */
char *os_read_agent_ip()
{
    char buf[1024 + 1];
    FILE *fp;

    mdebug2("Calling os_read_agent_ip().");

    fp = wfopen(AGENT_INFO_FILE, "r");
    if (!fp) {
        merror(FOPEN_ERROR, AGENT_INFO_FILE, errno, strerror(errno));
        return (NULL);
    }

    buf[1024] = '\0';

    /* Get IP */
    if (fgets(buf, 1024, fp) && fgets(buf, 1024, fp)) {
        char *ret = NULL;
        os_strdup(buf, ret);
        fclose(fp);

        return (ret);
    }

    fclose(fp);
    return (NULL);
}

/* Read the agent id for the current agent
 * Returns NULL on error
 */
char *os_read_agent_id()
{
    char buf[1024 + 1];
    FILE *fp;

    mdebug2("Calling os_read_agent_id().");

    fp = wfopen(AGENT_INFO_FILE, "r");
    if (!fp) {
        merror(FOPEN_ERROR, AGENT_INFO_FILE, errno, strerror(errno));
        return (NULL);
    }

    buf[1024] = '\0';

    /* Get id */
    if (fgets(buf, 1024, fp) && fgets(buf, 1024, fp) && fgets(buf, 1024, fp)) {
        char *ret = NULL;
        os_strdup(buf, ret);
        fclose(fp);

        return (ret);
    }

    fclose(fp);
    return (NULL);
}

/*  Read the agent profile name for the current agent
 *  Returns NULL on error
 *
 *  Description:
 *  Comma separated list of strings that used to identify what type
 *  of configuration is used for this agent.
 *  The profile name is set in the agent's etc/ossec.conf file
 *  It is matched with the ossec manager's agent.conf file to read
 *  configuration only applicable to this profile name.
 */
char *os_read_agent_profile()
{
    char buf[1024 + 1];
    FILE *fp;

    mdebug2("Calling os_read_agent_profile().");
    fp = wfopen(AGENT_INFO_FILE, "r");

    if (!fp) {
        merror(FOPEN_ERROR, AGENT_INFO_FILE, errno, strerror(errno));
        return (NULL);
    }

    buf[1024] = '\0';

    /* Get profile */
    if (fgets(buf, 1024, fp) && fgets(buf, 1024, fp) &&
            fgets(buf, 1024, fp) && fgets(buf, 1024, fp)) {
        char *ret = NULL;

        /* Trim the /n and/or /r at the end of the string */
        os_trimcrlf(buf);

        os_strdup(buf, ret);
        mdebug2("os_read_agent_profile() = [%s]", ret);

        fclose(fp);

        return (ret);
    }

    fclose(fp);
    return (NULL);
}

/* Write the agent info to the queue, for the other processes to read
 * Returns 1 on success or <= 0 on failure
 */
int os_write_agent_info(const char *agent_name, __attribute__((unused)) const char *agent_ip,
                        const char *agent_id, const char *cfg_profile_name)
{
    FILE *fp;

    fp = wfopen(AGENT_INFO_FILE, "w");
    if (!fp) {
        merror(FOPEN_ERROR, AGENT_INFO_FILE, errno, strerror(errno));
        return (0);
    }

    fprintf(
        fp,
        "%s\n-\n%s\n%s\n",
        agent_name,
        agent_id,
        (cfg_profile_name) ? cfg_profile_name : "-"
    );
    fclose(fp);
    return (1);
}

int w_validate_group_name(const char *group, char *response) {

    unsigned int i = 0;
    char valid_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:;_-=+!@(),";
    int offset = 0;
    int valid_chars_length = strlen(valid_chars);
    char *multigroup = strchr(group,MULTIGROUP_SEPARATOR);
    char *multi_group_cpy = NULL;
    char *save_ptr = NULL;

    os_calloc(OS_SIZE_65536,sizeof(char),multi_group_cpy);
    snprintf(multi_group_cpy,OS_SIZE_65536,"%s",group);

    if (strlen(group) == 0) {
        free(multi_group_cpy);
        mdebug1("At w_validate_group_name(): Group length is 0");
        if (response) {
            snprintf(response, 2048, "ERROR: Invalid group name: Empty Group");
        }
        return -8;
    }

    if (!multigroup && (strlen(group) > MAX_GROUP_NAME)) {
        free(multi_group_cpy);
        mdebug1("At w_validate_group_name(): Group length is over %d characters",MAX_GROUP_NAME);
        if (response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... group is too large", group);
        }
        return -2;
    }
    else if (multigroup && strlen(group) > OS_SIZE_65536 -1 ) {
        free(multi_group_cpy);
        mdebug1("At w_validate_group_name(): Multigroup length is over %d characters",OS_SIZE_65536);
        if (response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... multigroup is too large", group);
        }
        return -3;
    }

    /* Check if the group is only composed by ',' */
    unsigned int comas = 0;
    for (i = 0; i < strlen(group); i++) {
        if (group[i] == MULTIGROUP_SEPARATOR) {
            comas++;
        }
    }

    if (!multigroup) {
        offset = 1;
        valid_chars[valid_chars_length - offset] = '\0';
    }

    /* Check if the multigroups are empty or have consecutive ',' */
    if (multigroup) {

        const char delim[2] = ",";
        char *individual_group = strtok_r(multi_group_cpy, delim, &save_ptr);

        while( individual_group != NULL ) {

            /* Spaces are not allowed */
            if (strchr(individual_group,' ')) {
                free(multi_group_cpy);
                if (response) {
                    snprintf(response, 2048, "ERROR: Invalid group name: %.255s... white spaces are not allowed", group);
                }
                return -4;
            }

            /* Validate the individual group length */
            if (strlen(individual_group) > MAX_GROUP_NAME) {
                free(multi_group_cpy);
                if (response) {
                    snprintf(response, 2048, "ERROR: Invalid group name: %.255s... group is too large", individual_group);
                }
                return -7;
            }

            individual_group = strtok_r(NULL, delim, &save_ptr);
        }

        /* Look for consecutive ',' */
        if (strstr(group,",,")) {
            free(multi_group_cpy);
            if (response) {
                snprintf(response, 2048, "ERROR: Invalid group name: %.255s... consecutive ',' are not allowed", group);
            }
            return -5;
        }
    }

    /* Check if the group is only composed by ',' */
    if (comas == strlen(group)) {
        free(multi_group_cpy);
        if (response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... characters '\\/:*?\"<>|,' are prohibited", group);
        }
        return -1;
    }

    /* Check if the group starts or ends with ',' */
    if (group[0] == ',' || group[strlen(group) - 1] == ',' ) {
        free(multi_group_cpy);
        if (response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... cannot start or end with ','", group);
        }
        return -6;
    }

    if (strspn(group,valid_chars) != strlen(group)) {
        free(multi_group_cpy);
        if (response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... characters '\\/:*?\"<>|,' are prohibited", group);
        }
        return -1;
    }

    free(multi_group_cpy);
    return 0;
}

// Connect to Agentd. Returns socket or -1 on error.
int auth_connect() {
#ifndef WIN32
    return OS_ConnectUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
#else
    return -1;
#endif
}

// Close socket if valid.
int auth_close(int sock) {
    return (sock >= 0) ? close(sock) : 0;
}

static cJSON* w_create_agent_add_payload(const char *name,
                                         const char *ip,
                                         const char *groups,
                                         const char *key_hash,
                                         const char *key,
                                         const char *id,
                                         authd_force_options_t *force_options) {
    cJSON* request = cJSON_CreateObject();
    cJSON* arguments = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "arguments", arguments);
    cJSON_AddStringToObject(request, "function", "add");
    cJSON_AddStringToObject(arguments, "name", name);
    cJSON_AddStringToObject(arguments, "ip", ip);

    if (groups) {
        cJSON_AddStringToObject(arguments, "groups", groups);
    }

    if (key_hash) {
        cJSON_AddStringToObject(arguments, "key_hash", key_hash);
    }

    if (key) {
        cJSON_AddStringToObject(arguments, "key", key);
    }

    if (id) {
        cJSON_AddStringToObject(arguments, "id", id);
    }

    cJSON* j_force = w_force_options_to_json(force_options);
    if(j_force){
        cJSON_AddItemToObject(arguments, "force", j_force);
    }

    return request;
}

static int w_parse_agent_add_response(const char* buffer, char *err_response, char* id, char* key, const int json_format, const int exit_on_error) {
    int result = 0;
    cJSON* response = NULL;
    cJSON * error = NULL;
    cJSON * message = NULL;
    cJSON * data = NULL;
    cJSON * data_id = NULL;
    cJSON * data_key = NULL;

    // Parse response
    const char *jsonErrPtr;
    if (response = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0), !response) {
        if (exit_on_error) {
            merror_exit("Parsing JSON response.");
        }
        result = -2;
    } else {
        // Get error field
        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            if (exit_on_error) {
                merror_exit("No such status from response.");
            }
            result = -2;
        }
        else {
            // Error response
            if (error->valueint > 0) {
                message = cJSON_GetObjectItem(response, "message");
                if (json_format) {
                    printf("%s", buffer);
                }
                else {
                    mwarn("%d: %s", error->valueint, message ? message->valuestring : "(undefined)");
                }
                result = -1;
            }
            //Success response
            else {
                // Get data field
                if (data = cJSON_GetObjectItem(response, "data"), !data) {
                    if (exit_on_error) {
                        merror_exit("No data received.");
                    }
                    result = -2;
                }
                else {
                    // Get data information if required
                    if (id) {
                        if (data_id = cJSON_GetObjectItem(data, "id"), !data_id) {
                            if (exit_on_error) {
                                merror_exit("No id received.");
                            }
                            result = -2;
                        }
                        else {
                            strncpy(id, data_id->valuestring, FILE_SIZE);
                            id[FILE_SIZE] = '\0';
                        }
                    }
                    if (key && result == 0) {
                        if (data_key = cJSON_GetObjectItem(data, "key"), !data_key) {
                            if (exit_on_error) {
                                merror_exit("No key received.");
                            }
                            result = -2;
                        }
                        else {
                            strncpy(key, data_key->valuestring, KEYSIZE);
                            key[KEYSIZE] = '\0';
                        }
                    }
                }
            }
        }
    }

    // Create an error response if needed
    if (err_response) {
        if (result == -1) {
            snprintf(err_response, 2048, "ERROR: %s", message ? message->valuestring : "(undefined)");
        }
        else if (result == -2) {
            snprintf(err_response, 2048, "ERROR: Invalid message format");
        }
    }

    cJSON_Delete(response);

    return result;
}

#ifndef WIN32
cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message) {
    cJSON * request = cJSON_CreateObject();

    cJSON_AddStringToObject(request, "daemon_name", daemon_name);
    cJSON_AddItemToObject(request, "message", message);

    return request;
}

static cJSON* w_create_agent_remove_payload(const char *id, const int purge) {
    cJSON* request = cJSON_CreateObject();
    cJSON* arguments = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "arguments", arguments);
    cJSON_AddStringToObject(request, "function", "remove");
    cJSON_AddStringToObject(arguments, "id", id);
    if (purge >= 0) {
        cJSON_AddNumberToObject(arguments, "purge", purge);
    }

    return request;
}

static int w_parse_agent_remove_response(const char* buffer, char *err_response, const int json_format, const int exit_on_error) {
    int result = 0;
    cJSON* response = NULL;
    cJSON * error = NULL;
    cJSON * message = NULL;

    // Parse response
    const char *jsonErrPtr;
    if (response = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0), !response) {
        if (exit_on_error) {
            merror_exit("Parsing JSON response.");
        }
        result = -2;
        return result;
    }

    // Detect error field
    if (error = cJSON_GetObjectItem(response, "error"), !error) {
        if (exit_on_error) {
            merror_exit("No such status from response.");
        }
        result = -2;
    }
    // Error response
    else if (error->valueint > 0) {
        message = cJSON_GetObjectItem(response, "message");
        if (json_format) {
            printf("%s", buffer);
        } else {
            merror("%d: %s", error->valueint, message ? message->valuestring : "(undefined)");
        }
        result = -1;
    }

    // Create an error response if needed
    if (err_response) {
        if (result == -1) {
            snprintf(err_response, 2048, "ERROR: %s", message ? message->valuestring : "(undefined)");
        }
        else if (result == -2) {
            snprintf(err_response, 2048, "ERROR: Invalid message format");
        }
    }

    cJSON_Delete(response);

    return result;
}

int w_send_clustered_message(const char* command, const char* payload, char* response) {
    char sockname[PATH_MAX + 1] = {0};
    int sock = -1;
    int result = 0;
    int response_length = 0;
    int send_attempts = 0;
    bool send_error = FALSE;

    strcpy(sockname, CLUSTER_SOCK);
    for (send_attempts = 0; send_attempts < CLUSTER_SEND_MESSAGE_ATTEMPTS; ++send_attempts) {
        result = 0;
        send_error = FALSE;
        if (sock = external_socket_connect(sockname, WAZUH_IPC_TIMEOUT), sock >= 0) {
            if (OS_SendSecureTCPCluster(sock, command, payload, strlen(payload)) >= 0) {
                if (response_length = OS_RecvSecureClusterTCP(sock, response, OS_MAXSTR), response_length <= 0) {
                    switch (response_length) {
                    case -2:
                        mwarn("Cluster error detected");
                        send_error = TRUE;
                        break;
                    case -1:
                        mwarn("OS_RecvSecureClusterTCP(): %s", strerror(errno));
                        send_error = TRUE;
                        break;
                    case 0:
                        mdebug1("Empty message from local client.");
                        break;
                    case OS_MAXLEN:
                        merror("Received message > %i", OS_MAXSTR);
                        break;
                    }
                    result = -1;
                }
            }
            else {
                mwarn("OS_SendSecureTCPCluster(): %s", strerror(errno));
                send_error = TRUE;
                result = -2;
            }
            close(sock);
        }
        else {
            mwarn("Could not connect to socket '%s': %s (%d).", sockname, strerror(errno), errno);
            result = -2;
            send_error = TRUE;
        }

        if (!send_error) {
            break;
        } else if (send_attempts == CLUSTER_SEND_MESSAGE_ATTEMPTS - 1) {
            merror("Could not send message through the cluster after '%d' attempts.", CLUSTER_SEND_MESSAGE_ATTEMPTS);
        } else {
            sleep(1);
        }
    }

    return result;
}

//Send a clustered agent add request.
int w_request_agent_add_clustered(char *err_response,
                                  const char *name,
                                  const char *ip,
                                  const char *groups,
                                  const char *key_hash,
                                  char **id,
                                  char **key,
                                  authd_force_options_t *force_options,
                                  const char *agent_id) {
    int result;
    char response[OS_MAXSTR + 1];
    char new_id[FILE_SIZE+1] = { '\0' };
    char new_key[KEYSIZE+1] = { '\0' };
    cJSON* message;

    if (agent_id){
        // Create agent key request
        message = w_create_agent_add_payload(name, ip, groups, NULL, key_hash, agent_id, force_options);
    } else {
        // Create dispatching request
        message = w_create_agent_add_payload(name, ip, groups, key_hash, *key, agent_id, force_options);
    }
    cJSON* payload = w_create_sendsync_payload("authd", message);
    char* output = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if (result = w_send_clustered_message("sendsync", output, response), result == 0) {
        result = w_parse_agent_add_response(response, err_response, new_id, new_key, FALSE, FALSE);
    }
    else if (err_response) {
        snprintf(err_response, 2048, "ERROR: Cannot comunicate with master");
    }

    free(output);
    if (0 == result) {
        os_strdup(new_id, *id);
        os_strdup(new_key, *key);
    }


    return result;
}

//Send a clustered agent remove request.
int w_request_agent_remove_clustered(char *err_response, const char* agent_id, int purge) {
    int result;
    char response[OS_MAXSTR + 1];

    cJSON* message = w_create_agent_remove_payload(agent_id, purge);
    cJSON* payload = w_create_sendsync_payload("authd", message);
    char* output = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if (result = w_send_clustered_message("sendsync", output, response), result == 0) {
        result = w_parse_agent_remove_response(response, err_response, FALSE, FALSE);
    }
    else if (err_response) {
        snprintf(err_response, 2048, "ERROR: Cannot comunicate with master");
    }

    free(output);

    return result;
}
#endif //!WIN32

//Send a local agent add request.
int w_request_agent_add_local(int sock, char *id, const char *name, const char *ip, const char *groups, const char *key, authd_force_options_t *force_options, const int json_format, const char *agent_id, int exit_on_error) {
    int result;

    cJSON* payload = w_create_agent_add_payload(name, ip, groups, NULL, key, agent_id, force_options);
    char* output = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if (OS_SendSecureTCP(sock, strlen(output), output) < 0) {
        if (exit_on_error) {
            merror_exit("OS_SendSecureTCP(): %s", strerror(errno));
        }
        free(output);
        result = -2;
        return result;
    }
    free(output);

    char response[OS_MAXSTR + 1];
    ssize_t length;
    if (length = OS_RecvSecureTCP(sock, response, OS_MAXSTR), length < 0) {
        if (exit_on_error) {
            merror_exit("OS_RecvSecureTCP(): %s", strerror(errno));
        }
        result = -1;
        return result;
    } else if (length == 0) {
        if (exit_on_error) {
            merror_exit("Empty message from local server.");
        }
        result = -1;
        return result;
    } else {
        response[length] = '\0';
        result = w_parse_agent_add_response(response, NULL, id, NULL, json_format, exit_on_error);
    }

    return result;
}


char * get_agent_id_from_name(const char *agent_name) {

    FILE *fp;
    char *path = NULL;
    char *buffer = NULL;

    os_calloc(PATH_MAX,sizeof(char),path);
    os_calloc(OS_SIZE_65536 + 1,sizeof(char),buffer);

    snprintf(path,PATH_MAX,"%s", KEYS_FILE);

    fp = wfopen(path, "r");

    if (!fp) {
        mdebug1("Couldnt open file '%s'", KEYS_FILE);
        os_free(path);
        os_free(buffer);
        return NULL;
    }

    os_free(path);

    while(fgets (buffer, OS_SIZE_65536, fp) != NULL) {

        char **parts;

        parts = OS_StrBreak(' ',buffer,4);

        if (!parts) {
            continue;
        }

        // Make sure we have 4 parts
        int count = 0;
        int j;
        for (j = 0; parts[j]; j++) {
            count++;
        }

        if (count < 3) {
            free_strarray(parts);
            os_free(buffer);
            fclose(fp);
            return NULL;
        }

        // If the agent name is the same, return its ID
        if (strcmp(parts[1],agent_name) == 0) {
            char *id = strdup(parts[0]);
            fclose(fp);
            free_strarray(parts);
            os_free(buffer);
            return id;
        }

        free_strarray(parts);
    }

    fclose(fp);
    os_free(buffer);

    return NULL;
}

cJSON* w_force_options_to_json(authd_force_options_t *force_options){
    if(!force_options){
        return NULL;
    }

    cJSON* j_force_options = cJSON_CreateObject();
    cJSON* j_disconnected_time = cJSON_CreateObject();

    cJSON_AddBoolToObject(j_disconnected_time, "enabled", force_options->disconnected_time_enabled);
    cJSON_AddNumberToObject(j_disconnected_time, "value", force_options->disconnected_time);
    cJSON_AddItemToObject(j_force_options, "disconnected_time", j_disconnected_time);

    cJSON_AddBoolToObject(j_force_options, "enabled", force_options->enabled);
    cJSON_AddBoolToObject(j_force_options, "key_mismatch", force_options->key_mismatch);
    cJSON_AddNumberToObject(j_force_options, "after_registration_time", force_options->after_registration_time);

    return j_force_options;
}

/* Connect to the control socket if available */
#if defined (__linux__) || defined (__MACH__) || defined(sun) || defined(FreeBSD) || defined(OpenBSD)
int control_check_connection() {
    int sock = OS_ConnectUnixDomain(CONTROL_SOCK, SOCK_STREAM, OS_SIZE_128);

    if (sock < 0) {
        return -1;
    } else {
        return sock;
    }
}
#endif

/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/sha256/sha256_op.h"
#include "../os_net/os_net.h"
#include "../addagent/manage_agents.h"
#include "syscheckd/syscheck.h"

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

/// Pending restart bit field
static struct {
    unsigned syscheck:1;
    unsigned rootcheck:1;
} os_restart;

#ifndef WIN32
//Sends message thru the cluster
static int w_send_clustered_message(const char* command, const char* payload, char* response);

//Alloc and create sendsync command payload
static cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message);

//Alloc and create an agent removal command payload
static cJSON* w_create_agent_remove_payload(const char *id, const int purge);

//Parse an agent removal response
static int w_parse_agent_remove_response(const char* buffer, char *err_response, const int json_format, const int exit_on_error);
#endif

//Parse an agent addition response
static int w_parse_agent_add_response(const char* buffer, char *err_response, char* id, char* key, const int json_format, const int exit_on_error);

//Alloc and create an agent addition command payload
static cJSON* w_create_agent_add_payload(const char *name, const char *ip, const char * groups, const char *key, const int force, const char *id);

/* Check if syscheck is to be executed/restarted
 * Returns 1 on success or 0 on failure (shouldn't be executed now)
 */
int os_check_restart_syscheck()
{
    int current = os_restart.syscheck;
    os_restart.syscheck = 0;
    return current;
}

/* Check if rootcheck is to be executed/restarted
 * Returns 1 on success or 0 on failure (shouldn't be executed now)
 */
int os_check_restart_rootcheck()
{
    int current = os_restart.rootcheck;
    os_restart.rootcheck = 0;
    return current;
}

/* Set syscheck and rootcheck to be restarted */
void os_set_restart_syscheck()
{
    os_restart.syscheck = 1;
    os_restart.rootcheck = 1;
}

/* Read the agent name for the current agent
 * Returns NULL on error
 */
char *os_read_agent_name()
{
    char buf[1024 + 1];
    FILE *fp = NULL;

    mdebug2("Calling os_read_agent_name().");

    if (isChroot()) {
        fp = fopen(AGENT_INFO_FILE, "r");
    } else {
        fp = fopen(AGENT_INFO_FILEP, "r");
    }

    /* We give 1 second for the file to be created */
    if (!fp) {
        sleep(1);

        if (isChroot()) {
            fp = fopen(AGENT_INFO_FILE, "r");
        } else {
            fp = fopen(AGENT_INFO_FILEP, "r");
        }
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

    fp = fopen(AGENT_INFO_FILE, "r");
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

    fp = fopen(AGENT_INFO_FILE, "r");
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

    if (isChroot()) {
        fp = fopen(AGENT_INFO_FILE, "r");
    } else {
        fp = fopen(AGENT_INFO_FILEP, "r");
    }

    if (!fp) {
        mdebug2("Failed to open file. Errno=%d.", errno);
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

    fp = fopen(isChroot() ? AGENT_INFO_FILE : AGENT_INFO_FILEP, "w");
    if (!fp) {
        merror(FOPEN_ERROR, isChroot() ? AGENT_INFO_FILE : AGENT_INFO_FILEP, errno, strerror(errno));
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

/* Read group. Returns 0 on success or -1 on failure. */
int get_agent_group(const char *id, char *group, size_t size) {
    char path[PATH_MAX];
    int result = 0;
    FILE *fp;

    if (snprintf(path, PATH_MAX, isChroot() ? GROUPS_DIR "/%s" : DEFAULTDIR GROUPS_DIR "/%s", id) >= PATH_MAX) {
        merror("At get_agent_group(): file path too large for agent '%s'.", id);
        return -1;
    }

    if (!(fp = fopen(path, "r"))) {
        mdebug2("At get_agent_group(): file '%s' not found.", path);
        return -1;
    }

    if (fgets(group, size, fp)) {
        char *endl = strchr(group, '\n');

        if (endl) {
            *endl = '\0';
        }
    } else {
        mwarn("Empty group for agent ID '%s'.", id);
        result = -1;
    }

    fclose(fp);
    return result;
}

/* Set agent group. Returns 0 on success or -1 on failure. */
int set_agent_group(const char * id, const char * group) {
    char path[PATH_MAX];
    FILE *fp;
    mode_t oldmask;

    if (snprintf(path, PATH_MAX, isChroot() ? GROUPS_DIR "/%s" : DEFAULTDIR GROUPS_DIR "/%s", id) >= PATH_MAX) {
        merror("At set_agent_group(): file path too large for agent '%s'.", id);
        return -1;
    }

    oldmask = umask(0006);
    fp = fopen(path, "w");
    umask(oldmask);

    if (!fp) {
        merror("At set_agent_group(): open(%s): %s", path, strerror(errno));
        return -1;
    }

    fprintf(fp, "%s\n", group);
    fclose(fp);

    // Check for multigroup

    return 0;
}

int set_agent_multigroup(char * group){
    int oldmask;
    char *multigroup = strchr(group,MULTIGROUP_SEPARATOR);

    if(!multigroup){
        return 0;
    }

    char *endl = strchr(group, '\n');

    if (endl) {
        *endl = '\0';
    }

    /* Remove multigroup if it's not used on any other agent */
    w_remove_multigroup(group);

    /* Check if the multigroup dir is created */
    os_sha256 multi_group_hash;
    char multigroup_path[PATH_MAX + 1] = {0};
    OS_SHA256_String(group,multi_group_hash);
    char _hash[9] = {0};

    strncpy(_hash,multi_group_hash,8);
    snprintf(multigroup_path,PATH_MAX,"%s/%s",isChroot() ?  MULTIGROUPS_DIR :  DEFAULTDIR MULTIGROUPS_DIR,_hash);
    DIR *dp;
    dp = opendir(multigroup_path);

    if(!dp){
        if (errno == ENOENT) {
            oldmask = umask(0002);
#ifndef WIN32
            int retval = mkdir(multigroup_path, 0770);
#else
            int retval = mkdir(multigroup_path);
#endif
            umask(oldmask);

            if (retval == -1) {
                mdebug1("At read_controlmsg(): couldn't create directory '%s'", multigroup_path);
                return -1;
            }
        } else {
            mwarn("Could not create directory '%s': %s (%d)", multigroup_path, strerror(errno), errno);
        }
    }else{
        closedir(dp);
    }

    return 0;
}

#ifndef WIN32
/* Create multigroup dir. Returns 0 on success or -1 on failure. */
int create_multigroup_dir(const char * multigroup) {
    char path[PATH_MAX];
    DIR *dp;
    char *has_multigroup =  strchr(multigroup,MULTIGROUP_SEPARATOR);

    if(!has_multigroup){
        return 0;
    }
    mdebug1("Attempting to create multigroup dir: '%s'",multigroup);

    if (snprintf(path, PATH_MAX, isChroot() ? MULTIGROUPS_DIR "/%s" : DEFAULTDIR MULTIGROUPS_DIR "/%s", multigroup) >= PATH_MAX) {
        merror("At create_multigroup_dir(): path too large for multigroup '%s'.", multigroup);
        return -1;
    }

    dp = opendir(path);

    /* Multigroup doesnt exists, create the directory */
    if(!dp){
       if (mkdir(path, 0770) == -1) {
            merror("At create_multigroup_dir(): couldn't create directory '%s'", path);
            return -1;
        }

        if(chmod(path,0770) < 0){
            merror("At create_multigroup_dir(): Error in chmod setting permissions for path: %s",path);
        }

        uid_t uid = Privsep_GetUser(USER);
        gid_t gid = Privsep_GetGroup(GROUPGLOBAL);

        if (chown(path, uid, gid) == -1) {
            merror(CHOWN_ERROR, path, errno, strerror(errno));
            return -1;
        }
        mdebug1("Multigroup dir created: '%s'",multigroup);
    }
    else{
        closedir(dp);
    }

    return 0;
}
#endif

/*
 * Parse manager hostname from agent-info file.
 * If no such file, returns NULL.
 */

char* hostname_parse(const char *path) {
    char buffer[OS_MAXSTR];
    char *key;
    char *value;
    char *end;
    char *manager_hostname;
    FILE *fp;

    if (!(fp = fopen(path, "r"))) {
        if (errno == ENOENT) {
            mdebug1(FOPEN_ERROR, path, errno, strerror(errno));
        } else {
            merror(FOPEN_ERROR, path, errno, strerror(errno));
        }

        return NULL;
    }

    os_calloc(OS_MAXSTR, sizeof(char), manager_hostname);

    while (fgets(buffer, OS_MAXSTR, fp)) {
        switch (*buffer) {
        case '#':
            if (buffer[1] == '\"') {
                key = buffer + 2;
            } else {
                continue;
            }

            break;
        default:
            continue;
        }

        if (!(value = strstr(key, "\":"))) {
            continue;
        }

        *value = '\0';
        value += 2;

        if (end = strchr(value, '\n'), !end) {
            continue;
        }

        snprintf(manager_hostname, OS_MAXSTR - 1, "%s", value);
    }

    fclose(fp);
    return manager_hostname;
}


int w_validate_group_name(const char *group, char *response){

    unsigned int i = 0;
    char valid_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:;_-=+!@(),";
    int offset = 0;
    int valid_chars_length = strlen(valid_chars);
    char *multigroup = strchr(group,MULTIGROUP_SEPARATOR);
    char *multi_group_cpy = NULL;
    char *save_ptr = NULL;

    os_calloc(OS_SIZE_65536,sizeof(char),multi_group_cpy);
    snprintf(multi_group_cpy,OS_SIZE_65536,"%s",group);

    if(strlen(group) == 0) {
        free(multi_group_cpy);
        mdebug1("At w_validate_group_name(): Group length is 0");
        if(response) {
            snprintf(response, 2048, "ERROR: Invalid group name: Empty Group");
        }
        return -8;
    }

    if(!multigroup && (strlen(group) > MAX_GROUP_NAME)){
        free(multi_group_cpy);
        mdebug1("At w_validate_group_name(): Group length is over %d characters",MAX_GROUP_NAME);
        if(response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... group is too large", group);
        }
        return -2;
    }
    else if(multigroup && strlen(group) > OS_SIZE_65536 -1 ){
        free(multi_group_cpy);
        mdebug1("At w_validate_group_name(): Multigroup length is over %d characters",OS_SIZE_65536);
        if(response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... multigroup is too large", group);
        }
        return -3;
    }

    /* Check if the group is only composed by ',' */
    unsigned int comas = 0;
    for(i = 0; i < strlen(group); i++){
        if(group[i] == MULTIGROUP_SEPARATOR){
            comas++;
        }
    }

    if(!multigroup){
        offset = 1;
        valid_chars[valid_chars_length - offset] = '\0';
    }

    /* Check if the multigroups are empty or have consecutive ',' */
    if(multigroup){

        const char delim[2] = ",";
        char *individual_group = strtok_r(multi_group_cpy, delim, &save_ptr);

        while( individual_group != NULL ) {

            /* Spaces are not allowed */
            if(strchr(individual_group,' '))
            {
                free(multi_group_cpy);
                if(response) {
                    snprintf(response, 2048, "ERROR: Invalid group name: %.255s... white spaces are not allowed", group);
                }
                return -4;
            }

            /* Validate the individual group length */
            if (strlen(individual_group) > MAX_GROUP_NAME) {
                free(multi_group_cpy);
                if (response){
                    snprintf(response, 2048, "ERROR: Invalid group name: %.255s... group is too large", individual_group);
                }
                return -7;
            }

            individual_group = strtok_r(NULL, delim, &save_ptr);
        }

        /* Look for consecutive ',' */
        if(strstr(group,",,")){
            free(multi_group_cpy);
            if(response) {
                snprintf(response, 2048, "ERROR: Invalid group name: %.255s... consecutive ',' are not allowed", group);
            }
            return -5;
        }
    }

    /* Check if the group is only composed by ',' */
    if(comas == strlen(group)){
        free(multi_group_cpy);
        if(response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... characters '\\/:*?\"<>|,' are prohibited", group);
        }
        return -1;
    }

    /* Check if the group starts or ends with ',' */
    if(group[0] == ',' || group[strlen(group) - 1] == ',' ){
        free(multi_group_cpy);
        if(response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... cannot start or end with ','", group);
        }
        return -6;
    }

    if(strspn(group,valid_chars) != strlen(group)){
        free(multi_group_cpy);
        if(response) {
            snprintf(response, 2048, "ERROR: Invalid group name: %.255s... characters '\\/:*?\"<>|,' are prohibited", group);
        }
        return -1;
    }

    free(multi_group_cpy);
    return 0;
}

void w_remove_multigroup(const char *group){
    char *multigroup = strchr(group,MULTIGROUP_SEPARATOR);
    char path[PATH_MAX + 1] = {0};

    if(multigroup){
        sprintf(path,"%s",isChroot() ?  GROUPS_DIR :  DEFAULTDIR GROUPS_DIR);

        if(wstr_find_in_folder(path,group,1) < 0){
            /* Remove the DIR */
            os_sha256 multi_group_hash;
            OS_SHA256_String(group,multi_group_hash);
            char _hash[9] = {0};

            /* We only want the 8 first bytes of the hash */
            multi_group_hash[8] = '\0';

            strncpy(_hash,multi_group_hash,8);

            sprintf(path,"%s/%s",isChroot() ? MULTIGROUPS_DIR : DEFAULTDIR MULTIGROUPS_DIR,_hash);

            if (rmdir_ex(path) != 0) {
                mdebug1("At w_remove_multigroup(): Directory '%s' couldn't be deleted. ('%s')",path, strerror(errno));
            }
        }
    }
}

// Connect to Agentd. Returns socket or -1 on error.
int auth_connect() {
#ifndef WIN32
    return OS_ConnectUnixDomain(isChroot() ? AUTH_LOCAL_SOCK : AUTH_LOCAL_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);
#else
    return -1;
#endif
}

// Close socket if valid.
int auth_close(int sock) {
    return (sock >= 0) ? close(sock) : 0;
}

static cJSON* w_create_agent_add_payload(const char *name, const char *ip, const char * groups, const char *key, const int force, const char *id) {
    cJSON* request = cJSON_CreateObject();
    cJSON* arguments = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "arguments", arguments);
    cJSON_AddStringToObject(request, "function", "add");
    cJSON_AddStringToObject(arguments, "name", name);
    cJSON_AddStringToObject(arguments, "ip", ip);

    if(groups) {
        cJSON_AddStringToObject(arguments, "groups", groups);
    }

    if(key) {
        cJSON_AddStringToObject(arguments, "key", key);
    }

    if(id) {
        cJSON_AddStringToObject(arguments, "id", id);
    }

    if (force >= 0) {
        cJSON_AddNumberToObject(arguments, "force", force);
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
        if(exit_on_error){
            merror_exit("Parsing JSON response.");
        }
        result = -2;
    }
    else {
        // Get error field
        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            if(exit_on_error){
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
                    merror("%d: %s", error->valueint, message ? message->valuestring : "(undefined)");
                }
                result = -1;
            }
            //Success response
            else {
                // Get data field
                if (data = cJSON_GetObjectItem(response, "data"), !data) {
                    if(exit_on_error){
                        merror_exit("No data received.");
                    }
                    result = -2;
                }
                else {
                    // Get data information if required
                    if (id) {
                        if (data_id = cJSON_GetObjectItem(data, "id"), !data_id) {
                            if(exit_on_error){
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
                            if(exit_on_error){
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
    if(err_response) {
        if(result == -1) {
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
static cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message) {
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
        if(exit_on_error){
            merror_exit("Parsing JSON response.");
        }
        result = -2;
        return result;
    }

    // Detect error field
    if (error = cJSON_GetObjectItem(response, "error"), !error) {
        if(exit_on_error){
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
    if(err_response) {
        if(result == -1) {
            snprintf(err_response, 2048, "ERROR: %s", message ? message->valuestring : "(undefined)");
        }
        else if (result == -2) {
            snprintf(err_response, 2048, "ERROR: Invalid message format");
        }
    }

    cJSON_Delete(response);

    return result;
}

static int w_send_clustered_message(const char* command, const char* payload, char* response) {
    char sockname[PATH_MAX + 1] = {0};
    int sock = -1;
    int result = 0;
    int response_length = 0;

    if (isChroot()) {
        strcpy(sockname, CLUSTER_SOCK);
    } else {
        strcpy(sockname, DEFAULTDIR CLUSTER_SOCK);
    }

    if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock >= 0) {
        if (OS_SendSecureTCPCluster(sock, command, payload, strlen(payload)) >= 0) {
            if(response_length = OS_RecvSecureClusterTCP(sock, response, OS_MAXSTR), response_length <= 0) {
                switch (response_length) {
                case -2:
                    merror("Cluster error detected");
                    break;
                case -1:
                    merror("OS_RecvSecureClusterTCP(): %s", strerror(errno));
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
        else{
            merror("OS_SendSecureTCPCluster(): %s", strerror(errno));
            result = -2;
        }
        close(sock);
    }
    else {
        merror("Could not connect to socket '%s': %s (%d).", sockname, strerror(errno), errno);
        result = -2;
    }

    return result;
}

//Send a clustered agent add request.
int w_request_agent_add_clustered(char *err_response, const char *name, const char *ip, const char * groups, char **id, char **key, const int force, const char *agent_id) {
    int result;
    char response[OS_MAXSTR + 1];
    char new_id[FILE_SIZE+1] = { '\0' };
    char new_key[KEYSIZE+1] = { '\0' };

    cJSON* message = w_create_agent_add_payload(name, ip, groups, *key, force, agent_id);
    cJSON* payload = w_create_sendsync_payload("authd", message);
    char* output = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if(result = w_send_clustered_message("sendsync", output, response), result == 0) {
        result = w_parse_agent_add_response(response, err_response, new_id, new_key, FALSE, FALSE);
    }
    else if(err_response) {
        snprintf(err_response, 2048, "ERROR: Cannot comunicate with master");
    }

    free(output);
    if(0 == result) {
        os_strdup(new_id, *id);
        os_strdup(new_key, *key);
    }


    return result;
}

//Send a clustered agent remove request.
int w_request_agent_remove_clustered(char *err_response, const char* agent_id, int purge){
    int result;
    char response[OS_MAXSTR + 1];

    cJSON* message = w_create_agent_remove_payload(agent_id, purge);
    cJSON* payload = w_create_sendsync_payload("authd", message);
    char* output = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if(result = w_send_clustered_message("sendsync", output, response), result == 0) {
        result = w_parse_agent_remove_response(response, err_response, FALSE, FALSE);
    }
    else if(err_response) {
        snprintf(err_response, 2048, "ERROR: Cannot comunicate with master");
    }

    free(output);

    return result;
}
#endif //!WIN32

//Send a local agent add request.
int w_request_agent_add_local(int sock, char *id, const char *name, const char *ip, const char *groups, const char *key, const int force, const int json_format, const char *agent_id, int exit_on_error){
    int result;

    cJSON* payload = w_create_agent_add_payload(name, ip, groups, key, force, agent_id);
    char* output = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if (OS_SendSecureTCP(sock, strlen(output), output) < 0) {
        if(exit_on_error){
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
        if(exit_on_error){
            merror_exit("OS_RecvSecureTCP(): %s", strerror(errno));
        }
        result = -1;
        return result;
    } else if (length == 0) {
        if(exit_on_error){
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

    snprintf(path,PATH_MAX,"%s",isChroot() ? KEYS_FILE : KEYSFILE_PATH);

    fp = fopen(path,"r");

    if(!fp) {
        mdebug1("Couldnt open file '%s'",path);
        os_free(path);
        os_free(buffer);
        return NULL;
    }

    os_free(path);

    while(fgets (buffer, OS_SIZE_65536, fp) != NULL) {

        char **parts;

        parts = OS_StrBreak(' ',buffer,4);

        if(!parts) {
            continue;
        }

        // Make sure we have 4 parts
        int count = 0;
        int j;
        for (j = 0; parts[j]; j++) {
            count++;
        }

        if(count < 3) {
            free_strarray(parts);
            os_free(buffer);
            fclose(fp);
            return NULL;
        }

        // If the agent name is the same, return its ID
        if(strcmp(parts[1],agent_name) == 0){
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

/* Connect to the control socket if available */
#if defined (__linux__) || defined (__MACH__) || defined(sun)
int control_check_connection() {
    int sock = OS_ConnectUnixDomain(CONTROL_SOCK_PATH, SOCK_STREAM, OS_SIZE_128);

    if (sock < 0) {
        return -1;
    } else {
        return sock;
    }
}
#endif

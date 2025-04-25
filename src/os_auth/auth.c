/* Auth Common
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 22, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include <stdio.h>
#include "auth.h"
#include "defs.h"
#include "os_err.h"
#include "string_op.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuh_db/wdb.h"

#ifdef WAZUH_UNIT_TESTING
#define static

// Redefine ossec_version
#undef __ossec_version
#define __ossec_version "v4.5.0"
#endif

keystore keys;
char shost[512];
authd_config_t config;

struct keynode *queue_insert = NULL;
struct keynode *queue_remove = NULL;
struct keynode * volatile *insert_tail;
struct keynode * volatile *remove_tail;

// Append key to insertion queue
void add_insert(const keyentry *entry,const char *group) {
    struct keynode *node;

    os_calloc(1, sizeof(struct keynode), node);
    node->id = strdup(entry->id);
    node->name = strdup(entry->name);
    node->ip = strdup(entry->ip->ip);
    node->raw_key = strdup(entry->raw_key);
    node->group = strdup(group ? group : "default");

    (*insert_tail) = node;
    insert_tail = &node->next;
}

// Append key to deletion queue
void add_remove(const keyentry *entry) {
    struct keynode *node;

    os_calloc(1, sizeof(struct keynode), node);
    node->id = strdup(entry->id);
    node->name = strdup(entry->name);
    node->ip = strdup(entry->ip->ip);

    (*remove_tail) = node;
    remove_tail = &node->next;
}


w_err_t w_auth_parse_data(const char* buf,
                          char *response,
                          const char *authpass,
                          char *ip,
                          char **agentname,
                          char **groups,
                          char **key_hash) {

    bool parseok = FALSE;
    /* Checking for shared password authentication. */
    if (authpass) {
        /* Format is pretty simple: OSSEC PASS: PASS WHATEVERACTION */
        parseok = FALSE;
        if (strncmp(buf, "OSSEC PASS: ", 12) == 0) {
            buf += 12;
            if (strlen(buf) > strlen(authpass) && strncmp(buf, authpass, strlen(authpass)) == 0) {
                buf += strlen(authpass);
                if (*buf == ' ') {
                    buf++;
                    parseok = 1;
                }
            }
        }

        if (parseok == 0) {
            merror("Invalid password provided by %s. Closing connection.", ip);
            snprintf(response, OS_SIZE_2048, "ERROR: Invalid password");
            return OS_INVALID;
        }
    }

    /* Checking for action A (add agent) */
    parseok = FALSE;
    if (strncmp(buf, "OSSEC A:'", 9) == 0) {
        buf += 9;

        unsigned len = 0;
        while (*buf != '\0') {
            if (*buf == '\'') {
                os_malloc(len+1, *agentname);
                memcpy(*agentname, buf-len, len);
                (*agentname)[len] = '\0';
                minfo("Received request for a new agent (%s) from: %s", *agentname, ip);
                parseok = TRUE;
                break;
            }
            len++;
            buf++;
        }
    }
    buf++;

    if (!parseok) {
        merror("Invalid request for new agent from: %s", ip);
        snprintf(response, OS_SIZE_2048, "ERROR: Invalid request for new agent");
        return OS_INVALID;
    }

    if (!OS_IsValidName(*agentname)) {
        merror("Invalid agent name: %s from %s", *agentname, ip);
        snprintf(response, OS_SIZE_2048, "ERROR: Invalid agent name: %s", *agentname);
        return OS_INVALID;
    }

    /* Check for valid agent version */
    const char * agent_version_token = " V:";
    if (strncmp(buf, agent_version_token, 3) == 0) {
        char version[OS_BUFFER_SIZE+1] = {0};
        sscanf(buf," V:\'%2048[^\']\"",version);

        /* Validate the version */
        if (buf[strlen(version) + 4] != '\'') {
            merror("Unterminated version field");
            snprintf(response, OS_SIZE_2048, "ERROR: Unterminated version field");
            return OS_INVALID;
        }

        if (!config.allow_higher_versions && compare_wazuh_versions(__ossec_version, version, false) < 0) {
            merror("Incompatible version for new agent from: %s", ip);
            snprintf(response, OS_SIZE_2048, "ERROR: %s", HC_INVALID_VERSION_RESPONSE);
            return OS_INVALID;
        }

        /* Forward the string pointer V:'........' 3 for " V:", 2 for '' */
        buf += strlen(version) + 5;
    }

    /* Check for valid centralized group */
    const char * centralized_group_token = " G:";
    if (strncmp(buf, centralized_group_token, 3) == 0) {
        char tmp_groups[OS_SIZE_65536+1] = {0};
        sscanf(buf," G:\'%65536[^\']\"",tmp_groups);

        /* Validate the group name */
        if (buf[strlen(tmp_groups) + 4] != '\'') {
            merror("Unterminated group field");
            snprintf(response, OS_SIZE_2048, "ERROR: Unterminated group field");
            return OS_INVALID;
        }

        if (0 > w_validate_group_name(tmp_groups, response)) {
            merror("Invalid group name: %.255s... ,",tmp_groups);
            return OS_INVALID;
        }
        *groups = wstr_delete_repeated_groups(tmp_groups);
        if (!*groups) {
            snprintf(response, OS_SIZE_2048, "ERROR: Insuficient memory");
            return OS_MEMERR;
        }
        mdebug1("Group(s) is: %s",*groups);

        /* Forward the string pointer G:'........' 3 for " G:", 2 for '' */
        buf += strlen(tmp_groups) + 5;
    }

    /* Check for IP when client uses -i option */
    char client_source_ip[IPSIZE + 1] = {0};
    const char * client_source_ip_token = " IP:";
    if (strncmp(buf, client_source_ip_token, 4) == 0) {
        char format[15];
        sprintf(format, " IP:\'%%%d[^\' ]\"", IPSIZE);
        sscanf(buf, format, client_source_ip);

        if (buf[strlen(client_source_ip) + 5] != '\'') {
            merror("Unterminated IP field");
            snprintf(response, OS_SIZE_2048, "ERROR: Unterminated IP field");
            return OS_INVALID;
        }

        /* If IP: != 'src' overwrite the provided ip */
        if (strncmp(client_source_ip,"src",3) != 0) {
            os_ip *aux_ip;
            os_calloc(1, sizeof(os_ip), aux_ip);
            if (!OS_IsValidIP(client_source_ip, aux_ip)) {
                merror("Invalid IP: '%s'", client_source_ip);
                snprintf(response, OS_SIZE_2048, "ERROR: Invalid IP: %s", client_source_ip);
                w_free_os_ip(aux_ip);
                return OS_INVALID;
            }
            snprintf(ip, IPSIZE, "%s", aux_ip->ip);
            w_free_os_ip(aux_ip);
        }

        /* Forward the string pointer IP:'........' 4 for " IP:", 2 for '' */
        buf += strlen(client_source_ip) + 6;
    } else {
        if (!config.flags.use_source_ip) {
            // use_source-ip = 0 and no -I argument in agent
            snprintf(ip, IPSIZE, "any");
        }
    }

    /* Check for key hash when the agent already has one*/
    const char * key_hash_token = " K:";
    if (strncmp(buf, key_hash_token, 3) == 0) {
        os_calloc(1, sizeof(os_sha1), *key_hash);
        char format[15] = {0};
        sprintf(format, " K:\'%%%ld[^\']\"", sizeof(os_sha1) - 1);
        sscanf(buf, format, *key_hash);

        if (buf[strlen(*key_hash) + 4] != '\'') {
            merror("Unterminated key field");
            snprintf(response, OS_SIZE_2048, "ERROR: Unterminated key field");
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}

w_err_t w_auth_replace_agent(keyentry *key,
                             const char *key_hash,
                             authd_force_options_t *force_options,
                             char** str_result) {

    cJSON *j_agent_info = NULL;
    cJSON *j_date_add = NULL;
    cJSON *j_disconnection_time = NULL;
    cJSON *j_connection_status = NULL;
    bool replace_agent = true;
    char message[OS_SIZE_128] = {0};

    /* Check if the agent replacement is allowed */
    if (!force_options->enabled) {
        snprintf(message, OS_SIZE_128, "Agent '%s' won't be removed because the force option is disabled.", key->id);
        os_strdup(message, *str_result);
        return OS_INVALID;
    }

    j_agent_info = wdb_get_agent_info(atoi(key->id), NULL);
    if (j_agent_info) {
        j_connection_status = cJSON_GetObjectItem(j_agent_info->child, "connection_status");
        j_disconnection_time = cJSON_GetObjectItem(j_agent_info->child, "disconnection_time");
        j_date_add = cJSON_GetObjectItem(j_agent_info->child, "date_add");
    }

    if (!j_agent_info || !j_connection_status || !j_disconnection_time || !j_date_add) {
        cJSON_Delete(j_agent_info);
        snprintf(message, OS_SIZE_128, "Failed to get agent-info for agent '%s'", key->id);
        os_strdup(message, *str_result);
        return OS_INVALID;
    }

    /* Check if the agent has been disconnected longer than the value specified in the configuration option*/
    if (force_options->disconnected_time_enabled) {
        if (strcmp(j_connection_status->valuestring, AGENT_CS_NEVER_CONNECTED)) {
            time_t time_since_disconnected = difftime(time(NULL), j_disconnection_time->valueint);
            if (!strcmp(j_connection_status->valuestring, AGENT_CS_DISCONNECTED) && j_disconnection_time->valueint > 0 && time_since_disconnected < force_options->disconnected_time) {
                snprintf(message, OS_SIZE_128, "Agent '%s' has not been disconnected long enough to be replaced.", key->id);
                os_strdup(message, *str_result);
                replace_agent = false;
            } else if (j_disconnection_time->valueint == 0) {
                snprintf(message, OS_SIZE_128, "Agent '%s' can't be replaced since it is not disconnected.", key->id);
                os_strdup(message, *str_result);
                replace_agent = false;
            }
        }
    }

    /* Check if the agent is old enough to be removed */
    if (replace_agent && force_options->after_registration_time > 0) {
        time_t agent_registration_time = difftime(time(NULL), j_date_add->valueint);
        if (agent_registration_time < force_options->after_registration_time) {
            snprintf(message, OS_SIZE_128, "Agent '%s' doesn't comply with the registration time to be removed.", key->id);
            os_strdup(message, *str_result);
            replace_agent = false;
        }
    }

    /* Check if the agent key is the same than the existent in the manager */
    if (replace_agent && key_hash && force_options->key_mismatch) {
        os_sha1 manager_key_hash;
        w_get_key_hash(key, manager_key_hash);
        if (!strcmp(manager_key_hash, key_hash)) {
            snprintf(message, OS_SIZE_128, "Agent '%s' key already exists on the manager.", key->id);
            os_strdup(message, *str_result);
            replace_agent = false;
        }
    }

    cJSON_Delete(j_agent_info);

    /* Replace the agent */
    if (replace_agent) {
        snprintf(message, OS_SIZE_128, "Removing old agent '%s' (id '%s').", key->name, key->id);
        os_strdup(message, *str_result);
        add_remove(key);
        OS_DeleteKey(&keys, key->id, 0);
        return OS_SUCCESS;
    }
    return OS_INVALID;
}

w_err_t w_auth_validate_data(char *response,
                             const char *ip,
                             const char *agentname,
                             const char *groups,
                             const char *key_hash) {
    int index = 0;
    char* str_result = NULL;
    w_err_t result = OS_SUCCESS;

    /* Validate the group(s) name(s) */
    if (groups) {
        result = w_auth_validate_groups(groups, response);
    }

    /* Check for duplicate IP */
    if (result != OS_INVALID && strcmp(ip, "any") != 0 && (index = OS_IsAllowedIP(&keys, ip), index >= 0)) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, &config.force_options, &str_result)) {
            minfo("Duplicate IP '%s'. %s", ip, str_result);
        } else {
            mwarn("Duplicate IP '%s', rejecting enrollment. %s", ip, str_result);
            snprintf(response, OS_SIZE_2048, "ERROR: Duplicate IP: %s", ip);
            result = OS_INVALID;
        }
    }

    /* Check whether the agent name is the same as the manager */
    if (result != OS_INVALID && !strcmp(agentname, shost)) {
        merror("Invalid agent name %s (same as manager)", agentname);
        snprintf(response, OS_SIZE_2048, "ERROR: Invalid agent name: %s", agentname);
        result = OS_INVALID;
    }

    /* Check for duplicate name */
    if (result != OS_INVALID && (index = OS_IsAllowedName(&keys, agentname), index >= 0)) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, &config.force_options, &str_result)) {
            minfo("Duplicate name. %s", str_result);
        } else {
            mwarn("Duplicate name '%s', rejecting enrollment. %s", agentname, str_result);
            snprintf(response, OS_SIZE_2048, "ERROR: Duplicate agent name: %s", agentname);
            result = OS_INVALID;
        }
    }

    os_free(str_result);
    return result;
}

w_err_t w_auth_add_agent(char *response, const char *ip, const char *agentname, char **id, char **key) {

    /* Add the new agent */
    int index;

    if (index = OS_AddNewAgent(&keys, NULL, agentname, ip, NULL), index < 0) {
        merror("Unable to add agent: %s (internal error)", agentname);
        snprintf(response, OS_SIZE_2048, "ERROR: Internal manager error adding agent: %s", agentname);
        return OS_INVALID;
    }

    os_strdup(keys.keyentries[index]->id, *id);
    os_strdup(keys.keyentries[index]->raw_key, *key);

    return OS_SUCCESS;
}

w_err_t w_auth_validate_groups(const char *groups, char *response) {
    int max_multigroups = 0;
    char *save_ptr = NULL;
    char *tmp_groups = NULL;
    const char delim[] = {MULTIGROUP_SEPARATOR,'\0'};
    w_err_t ret = OS_SUCCESS;

    os_strdup(groups, tmp_groups);
    char *group = strtok_r(tmp_groups, delim, &save_ptr);

    while ( group != NULL ) {
        max_multigroups++;
        DIR * dp;
        char dir[PATH_MAX + 1] = {0};

        /* Check limit */
        if (max_multigroups > MAX_GROUPS_PER_MULTIGROUP) {
            merror("Maximum multigroup reached: Limit is %d",MAX_GROUPS_PER_MULTIGROUP);
            if (response) {
                snprintf(response, OS_SIZE_2048, "ERROR: Maximum multigroup reached: Limit is %d", MAX_GROUPS_PER_MULTIGROUP);
            }
            ret = OS_INVALID;
            break;
        }

        snprintf(dir, PATH_MAX + 1, SHAREDCFG_DIR "/%s", group);
        dp = opendir(dir);
        if (!dp) {
            merror("Invalid group: %.255s",group);
            if (response) {
                snprintf(response, OS_SIZE_2048, "ERROR: Invalid group: %s", group);
            }
            ret = OS_INVALID;
            break;
        }

        group = strtok_r(NULL, delim, &save_ptr);
        closedir(dp);
    }
    os_free(tmp_groups);
    return ret;
}

char *w_generate_random_pass()
{
    int rand1;
    int rand2;
    char *rand3;
    char *rand4;
    os_md5 md1;
    os_md5 md3;
    os_md5 md4;
    char *fstring = NULL;
    char *str1 = NULL;
    int time_value = (int)time(NULL);

    rand1 = os_random();
    rand2 = os_random();

    rand3 = GetRandomNoise();
    rand4 = GetRandomNoise();

    OS_MD5_Str(rand3, -1, md3);
    OS_MD5_Str(rand4, -1, md4);

    const int requested_size = snprintf(NULL,
                                        0,
                                        "%d%d%s%d%s%s",
                                        time_value,
                                        rand1,
                                        getuname(),
                                        rand2,
                                        md3,
                                        md4);

    if (requested_size > 0) {
        os_calloc(requested_size + 1, sizeof(char), str1);
        const int requested_size_assignation = snprintf(str1,
                                                        requested_size + 1,
                                                        "%d%d%s%d%s%s",
                                                        time_value,
                                                        rand1,
                                                        getuname(),
                                                        rand2,
                                                        md3,
                                                        md4);

        if (requested_size_assignation > 0 && requested_size_assignation == requested_size) {
            OS_MD5_Str(str1, -1, md1);
            fstring = strdup(md1);
        }
    }

    free(rand3);
    free(rand4);
    os_free(str1);
    return(fstring);
}

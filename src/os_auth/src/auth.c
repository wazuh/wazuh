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
#include <sys/stat.h>
#include "auth.h"
#include "defs.h"
#include "os_err.h"
#include "string_op.h"
#include "wazuhdb_queries_op.h"
#include "wdb.h"

#ifdef WAZUH_UNIT_TESTING
#define static

// Redefine wazuh_version
#undef __wazuh_version
#define __wazuh_version "v5.0.0"
#endif

typedef enum {
    PASS_LINE_OK = 0,
    PASS_LINE_INVALID,  /* missing, empty, or <= 2 chars after trimming */
    PASS_LINE_TOO_LONG
} pass_line_t;

keystore keys;
char shost[512];
authd_config_t config;

struct keynode *queue_insert = NULL;
struct keynode *queue_remove = NULL;
struct keynode * volatile *insert_tail;
struct keynode * volatile *remove_tail;

/* The queue between the writer thread and the relay that talks to the inventory sync server.
 *
 * Its own mutex and condition variable, deliberately NOT mutex_keys: the whole point is that the
 * thread which persists client.keys stops waiting on anything, so it must never contend with the
 * relay for the lock the enrollment path also takes.
 *
 * Only agent ids travel here, so the memory cost is a few dozen bytes per pending deletion. The cap
 * is not about memory: it is there so an inventory sync server that has been unreachable for hours
 * cannot grow this without bound in silence -- past it, the push is REFUSED and says so, naming the
 * agent, because a deletion the operator can repeat is better than an invisible backlog. */
#define PURGE_QUEUE_MAX_ENTRIES 65536

/* Retry interval when the delay is disabled (purge_delay = 0, i.e. tests): even then a failed
 * relay must not spin. */
#define PURGE_RETRY_FLOOR_SECONDS 5

typedef struct purge_node {
    char *id;
    /// Wall-clock second the deletion was requested. Persisted, and only ever used to work out how
    /// much of the delay is left; never to decide "is it due now" -- see due_mono.
    time_t requested_at;
    /// Monotonic second this entry may be sent. Monotonic ON PURPOSE: an NTP correction while the
    /// daemon runs must not be able to bring a purge forward, nor park it in a future that the
    /// wall clock has already left behind.
    time_t due_mono;
    /// Failed relay attempts, for log throttling only. Not persisted: a restart re-arms anyway.
    unsigned int attempts;
    struct purge_node *next;
} purge_node_t;

static purge_node_t *purge_queue = NULL;
static purge_node_t **purge_tail = &purge_queue;
static unsigned int purge_queue_size = 0;
static pthread_mutex_t mutex_purge = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_purge;
/// True when cond_purge counts on CLOCK_MONOTONIC, so its timed waits are immune to clock changes
/// too. False only on a platform that refuses the attribute, where the timed wait falls back to
/// the wall clock (the due-time decision stays monotonic either way).
static bool purge_cond_monotonic = false;
/// Highest agent id ever handed out, persisted alongside the queue. Guarded by mutex_purge.
static int purge_last_id = 0;
/// Set by purge_queue_stop() to release the relay. The queue owns its own stop flag rather than
/// reading the daemon's `running`, which lives in main-server.c: that file is deliberately left out
/// of authd_lib, so depending on it here would make this code impossible to unit-test.
static bool purge_stopping = false;

/// An id that has left the keystore but whose purge the writer has not queued yet.
///
/// The delete response goes out as soon as the key is dropped from memory, while the purge is only
/// queued by the writer, after it has rewritten client.keys. Without this list an insertion naming
/// that same id would find it free in both guards -- gone from the keystore, not yet in the queue --
/// and the purge, queued a moment later, would delete the NEW agent's documents. Under a bulk
/// deletion the writer takes seconds to reach the last entry, so the window is not theoretical.
///
/// In memory only, on purpose: nothing about a removal is persisted before client.keys is rewritten,
/// and a crash in that window leaves the agent still listed there, holding its id legitimately.
typedef struct purge_reserved {
    char *id;
    struct purge_reserved *next;
} purge_reserved_t;

/// Guarded by mutex_purge, like the queue it feeds.
static purge_reserved_t *purge_reserved = NULL;

/// Reserve an id at removal time. Idempotent: an id cannot leave the keystore twice without the
/// writer running in between, but a repeat must not grow the list either way.
static void purge_reserve_id(const char *agent_id) {
    purge_reserved_t *node;

    if (!agent_id) {
        return;
    }

    w_mutex_lock(&mutex_purge);

    for (node = purge_reserved; node; node = node->next) {
        if (!strcmp(node->id, agent_id)) {
            w_mutex_unlock(&mutex_purge);
            return;
        }
    }

    os_calloc(1, sizeof(purge_reserved_t), node);
    os_strdup(agent_id, node->id);
    node->next = purge_reserved;
    purge_reserved = node;

    w_mutex_unlock(&mutex_purge);
}

/// Drop a reservation, with mutex_purge already held. Called once the id's fate is settled: either
/// the queue owns it now, or it was refused and will never be purged at all.
static void purge_unreserve_id_locked(const char *agent_id) {
    purge_reserved_t **prev;
    purge_reserved_t *node;

    for (prev = &purge_reserved; (node = *prev) != NULL; prev = &node->next) {
        if (!strcmp(node->id, agent_id)) {
            *prev = node->next;
            os_free(node->id);
            os_free(node);
            return;
        }
    }
}

/* Static regex for group validation */
static regex_t w_auth_group_regex;
static bool w_auth_group_regex_compiled = false;
static pthread_mutex_t w_auth_group_regex_mutex = PTHREAD_MUTEX_INITIALIZER;

// Append key to insertion queue
void add_insert(const keyentry *entry,const char *group) {
    struct keynode *node;

    os_calloc(1, sizeof(struct keynode), node);
    node->id = strdup(entry->id);
    node->name = strdup(entry->name);
    node->ip = strdup(entry->ip->ip);
    node->raw_key = strdup(entry->raw_key);
    node->group = group ? strdup(group) : NULL;

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

    // Before this returns, and therefore before the caller answers the deletion: from here on an
    // insertion naming this id is refused until the writer has queued the purge for real.
    purge_reserve_id(entry->id);
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
            minfo("Invalid password provided by %s. Closing connection.", ip);
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
                mdebug1("Received request for a new agent (%s) from: %s", *agentname, ip);
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

        if (!config.allow_higher_versions && compare_wazuh_versions(__wazuh_version, version, false) < 0) {
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
                             char** str_result,
                             bool *warn) {

    cJSON *j_agent_info = NULL;
    cJSON *j_date_add = NULL;
    cJSON *j_disconnection_time = NULL;
    cJSON *j_connection_status = NULL;
    bool replace_agent = true;
    char message[OS_SIZE_128] = {0};

    if (warn) {
        *warn = false;
    }

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
                if (warn) {
                    *warn = true;
                }
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
    bool warn = false;

    /* Validate the group(s) name(s) */
    if (groups) {
        result = w_auth_validate_groups(groups, response);
    }

    /* Check for duplicate IP */
    if (result != OS_INVALID && strcmp(ip, "any") != 0 && (index = OS_IsAllowedIP(&keys, ip), index >= 0)) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, &config.force_options, &str_result, &warn)) {
            minfo("Duplicate IP '%s'. %s", ip, str_result);
        } else {
            if (warn) {
                mwarn("Duplicate IP '%s', rejecting enrollment. %s", ip, str_result);
            } else {
                minfo("Duplicate IP '%s', rejecting enrollment. %s", ip, str_result);
            }
            snprintf(response, OS_SIZE_2048, "ERROR: Duplicate IP: %s", ip);
            result = OS_INVALID;
        }
    }

    /* Check for duplicate name */
    if (result != OS_INVALID && (index = OS_IsAllowedName(&keys, agentname), index >= 0)) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, &config.force_options, &str_result, &warn)) {
            minfo("Duplicate name. %s", str_result);
        } else {
            if (warn) {
                mwarn("Duplicate name '%s', rejecting enrollment. %s", agentname, str_result);
            } else {
                minfo("Duplicate name '%s', rejecting enrollment. %s", agentname, str_result);
            }
            snprintf(response, OS_SIZE_2048, "ERROR: Duplicate agent name: %s", agentname);
            result = OS_INVALID;
        }
    }

    os_free(str_result);
    return result;
}

w_err_t w_auth_add_agent(char *response, const char *ip, const char *agentname, char **id, char **key) {

    /* Add the new agent */
    int index = OS_AddNewAgent(&keys, NULL, agentname, ip, NULL, config.max_agents);

    if (index == OS_ADDAGENT_LIMIT_REACHED) {
        merror("Unable to add agent: %s. Agent limit (%u) reached.", agentname, config.max_agents);
        snprintf(response,
                 OS_SIZE_2048,
                 "ERROR: Agent limit (%u) reached",
                 config.max_agents);
        return OS_INVALID;
    }

    if (index < 0) {
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

    /* Compile regex once on first call */
    w_mutex_lock(&w_auth_group_regex_mutex);
    if (!w_auth_group_regex_compiled) {
        if (regcomp(&w_auth_group_regex, "^[a-zA-Z0-9_\\.\\-]+$", REG_EXTENDED | REG_NOSUB) != 0) {
            merror("Failed to compile group validation regex");
            w_mutex_unlock(&w_auth_group_regex_mutex);
            if (response) {
                snprintf(response, OS_SIZE_2048, "ERROR: Internal validation error");
            }
            return OS_INVALID;
        }
        w_auth_group_regex_compiled = true;
    }

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

        /* Validate group name format */
        if (regexec(&w_auth_group_regex, group, 0, NULL, 0) != 0) {
            merror("Invalid group name '%s': contains forbidden characters", group);
            if (response) {
                snprintf(response, OS_SIZE_2048, "ERROR: Invalid group name: %s", group);
            }
            ret = OS_INVALID;
            break;
        }

        /* Explicit check for directory references (. and ..) */
        if (strcmp(group, ".") == 0 || strcmp(group, "..") == 0) {
            merror("Invalid group name '%s': directory reference not allowed", group);
            if (response) {
                snprintf(response, OS_SIZE_2048, "ERROR: Invalid group name: %s", group);
            }
            ret = OS_INVALID;
            break;
        }

        /* Verify group directory exists (after validation) */
        snprintf(dir, PATH_MAX + 1, SHAREDCFG_DIR "/%s", group);
        dp = wopendir(dir);
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
    w_mutex_unlock(&w_auth_group_regex_mutex);
    os_free(tmp_groups);
    return ret;
}

void w_auth_validate_groups_cleanup(void) {
    w_mutex_lock(&w_auth_group_regex_mutex);
    if (w_auth_group_regex_compiled) {
        regfree(&w_auth_group_regex);
        w_auth_group_regex_compiled = false;
    }
    w_mutex_unlock(&w_auth_group_regex_mutex);
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

/* Read and trim (CR/LF) the first line of an open password file. Shared by both readers. */
static pass_line_t read_password_line(FILE *fp, char **out) {
    char buf[4096 + 1];

    *out = NULL;

    if (!fgets(buf, sizeof(buf), fp)) {
        return PASS_LINE_INVALID;
    }

    size_t len = strlen(buf);

    /* fgets filled the buffer without a newline: line exceeds the maximum length. */
    if (len == sizeof(buf) - 1 && buf[len - 1] != '\n') {
        return PASS_LINE_TOO_LONG;
    }

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    if (len <= 2) {
        return PASS_LINE_INVALID;
    }

    /* Reject all-whitespace content: it passes the length check but would otherwise
     * become a valid shared enrollment secret, contradicting the fail-closed contract. */
    bool all_space = true;
    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)buf[i])) {
            all_space = false;
            break;
        }
    }
    if (all_space) {
        return PASS_LINE_INVALID;
    }

    *out = strdup(buf);
    return PASS_LINE_OK;
}

char *w_authd_load_password(const char *path, bool *generated) {
    FILE *fp;

    *generated = false;

    if (fp = wfopen(path, "r"), fp) {
        char *pass = NULL;
        pass_line_t status = read_password_line(fp, &pass);

        fclose(fp);

        /* Fail closed: an invalid existing file must never disable password enrollment. */
        switch (status) {
        case PASS_LINE_TOO_LONG:
            merror_exit("Authentication password in '%s' is too long.", path);
        case PASS_LINE_INVALID:
            merror_exit("Invalid password provided in '%s'.", path);
        case PASS_LINE_OK:
            return pass;
        }

        return pass;
    }

    /* No file: generate and persist. umask 0137 (file mode 0640) avoids a world-readable create/chmod window. */
    char *pass = w_generate_random_pass();

    if (!pass) {
        merror_exit("Unable to generate random password. Exiting.");
    }

    mode_t old_umask = umask(0137);
    fp = wfopen(path, "w");
    int saved_errno = errno;    /* before umask() can clobber it */
    umask(old_umask);

    if (!fp) {
        os_free(pass);
        merror_exit("Unable to write authentication password to '%s': %s", path, strerror(saved_errno));
    }

    if (fprintf(fp, "%s\n", pass) != (int)(strlen(pass) + 1)) {
        fclose(fp);
        os_free(pass);
        merror_exit("Unable to persist authentication password to '%s'.", path);
    }

    if (fclose(fp) != 0) {
        saved_errno = errno;
        os_free(pass);
        merror_exit("Unable to close authentication password file '%s': %s", path, strerror(saved_errno));
    }

    *generated = true;
    return pass;
}

/* Read-only loader for cluster workers: never generates, persists, nor exits. */
char *w_authd_read_password(const char *path) {
    FILE *fp;

    if (fp = wfopen(path, "r"), !fp) {
        return NULL;
    }

    char *pass = NULL;
    pass_line_t status = read_password_line(fp, &pass);

    fclose(fp);

    /* Distinguish a corrupt/malformed file from a file that is simply absent. Both
     * return NULL to the caller, but the former warrants a distinct log entry so
     * operators can tell a sync-lag apart from file corruption. */
    if (status == PASS_LINE_TOO_LONG) {
        mwarn("Authentication password in '%s' is too long; ignoring.", path);
    } else if (status == PASS_LINE_INVALID) {
        mwarn("Authentication password in '%s' is invalid or empty; ignoring.", path);
    }

    return pass;
}

/**
 * @brief Give cond_purge a monotonic clock, so its timed waits cannot be moved by an NTP jump.
 *
 * Called from main() before any thread exists. A platform that refuses the attribute still works:
 * the fallback only makes the WAIT drift with the wall clock, never the due-time decision.
 */
void purge_queue_init(void) {
#ifdef CLOCK_MONOTONIC
    pthread_condattr_t attr;

    if (pthread_condattr_init(&attr) == 0) {
        if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0) {
            purge_cond_monotonic = true;
        }
        w_cond_init(&cond_purge, purge_cond_monotonic ? &attr : NULL);
        pthread_condattr_destroy(&attr);

        if (!purge_cond_monotonic) {
            mdebug1("The deletion queue's condition variable could not be set to a monotonic clock.");
        }
        return;
    }
#endif
    w_cond_init(&cond_purge, NULL);
}

/**
 * @brief Persist the queue. The caller MUST hold mutex_purge.
 *
 * Rewrites the whole file into a temporary and renames it over the target, the same way
 * OS_WriteKeys() persists client.keys: a partial write can then never be observed, and the file is
 * small enough (an id and a timestamp per pending deletion) that rewriting it beats maintaining
 * tombstones. `last_update` is what lets the next start tell that the clock moved backwards.
 */
static void purge_file_write_locked(void) {
    File file;
    purge_node_t *node;

    if (TempFile(&file, PENDING_PURGES_FILE, 0) < 0) {
        mwarn("Could not open a temporary file for '%s': %s. The pending deletions are still queued in "
              "memory, but a restart would lose them.", PENDING_PURGES_FILE, strerror(errno));
        return;
    }

    if (fprintf(file.fp, "last_update %ld\n", (long)time(NULL)) < 0) {
        goto error;
    }

    /* The high-water mark of handed-out ids. It lives here rather than being derived from
     * client.keys because that is exactly the case it has to survive: deleting the highest ids
     * removes them from client.keys, and a restart would otherwise rebuild the counter lower and
     * hand those very ids to new agents -- while their purges are still pending. */
    if (fprintf(file.fp, "last_id %d\n", purge_last_id) < 0) {
        goto error;
    }

    for (node = purge_queue; node; node = node->next) {
        if (fprintf(file.fp, "purge %s %ld\n", node->id, (long)node->requested_at) < 0) {
            goto error;
        }
    }

    if (fclose(file.fp) != 0) {
        merror(FCLOSE_ERROR, file.name, errno, strerror(errno));
        goto error_closed;
    }

    if (OS_MoveFile(file.name, PENDING_PURGES_FILE) < 0) {
        goto error_closed;
    }

    os_free(file.name);
    return;

error:
    fclose(file.fp);
error_closed:
    mwarn("Could not write '%s'. The pending deletions are still queued in memory, but a restart "
          "would lose them.", PENDING_PURGES_FILE);
    unlink(file.name);
    os_free(file.name);
}

/**
 * @brief Queue an agent id for its indexer purge, and persist it. Called from the writer thread.
 *
 * Copies the id: the caller's keynode is freed a few lines later, so keeping its pointer would
 * leave the relay reading freed memory.
 */
void purge_queue_push(const char *agent_id) {
    purge_node_t *node;

    os_calloc(1, sizeof(purge_node_t), node);
    os_strdup(agent_id, node->id);
    node->requested_at = time(NULL);
    node->due_mono = w_get_monotonic_time() + config.purge_delay;

    w_mutex_lock(&mutex_purge);

    if (purge_queue_size >= PURGE_QUEUE_MAX_ENTRIES) {
        // Nothing will ever purge this id, so it must not stay reserved either.
        purge_unreserve_id_locked(agent_id);
        w_mutex_unlock(&mutex_purge);
        mwarn("The pending deletion queue is full (%d entries); the documents of agent '%s' were not "
              "queued for deletion. Repeat the deletion once the inventory sync server catches up.",
              PURGE_QUEUE_MAX_ENTRIES, agent_id);
        os_free(node->id);
        os_free(node);
        return;
    }

    (*purge_tail) = node;
    purge_tail = &node->next;
    purge_queue_size++;

    // The queue is the durable owner of this id now; the removal-time reservation can go.
    purge_unreserve_id_locked(agent_id);

    // Persisted BEFORE the relay is woken: if this crashed in between, the next start would replay
    // an entry that was never sent, which is exactly the direction we want to fail in.
    purge_file_write_locked();

    w_cond_signal(&cond_purge);
    w_mutex_unlock(&mutex_purge);
}

/**
 * @brief Release the relay from any wait it is in, so it can finish. Used by the shutdown path.
 */
void purge_queue_stop(void) {
    w_mutex_lock(&mutex_purge);
    purge_stopping = true;
    w_cond_broadcast(&cond_purge);
    w_mutex_unlock(&mutex_purge);
}

/**
 * @brief Whether this id still owes a purge.
 *
 * Handing such an id to a new agent would let the pending purge delete the NEW agent's documents:
 * the purge matches by agent id, and nothing in a state document distinguishes one owner from the
 * next (there is no timestamp, and two of the three indices in the scope carry no agent name).
 */
bool purge_is_pending(const char *agent_id) {
    bool pending = false;
    purge_node_t *node;

    if (!agent_id) {
        return false;
    }

    w_mutex_lock(&mutex_purge);

    for (node = purge_queue; node; node = node->next) {
        if (!strcmp(node->id, agent_id)) {
            pending = true;
            break;
        }
    }

    // Also the ids still on their way to the queue, or the window between the delete response and
    // the writer's pass would let an insertion reuse the id -- see purge_reserved.
    if (!pending) {
        purge_reserved_t *reserved;

        for (reserved = purge_reserved; reserved; reserved = reserved->next) {
            if (!strcmp(reserved->id, agent_id)) {
                pending = true;
                break;
            }
        }
    }

    w_mutex_unlock(&mutex_purge);
    return pending;
}

/**
 * @brief Record the highest id handed out, persisting it when it grows.
 *
 * Called from the writer thread with the id counter of the keystore snapshot it just wrote, so the
 * file can never claim an id that client.keys does not already account for.
 */
void purge_last_id_update(int id_counter) {
    bool grew = false;

    w_mutex_lock(&mutex_purge);

    if (id_counter > purge_last_id) {
        purge_last_id = id_counter;
        grew = true;
        purge_file_write_locked();
    }

    w_mutex_unlock(&mutex_purge);

    if (grew) {
        mdebug2("Highest agent id handed out is now %d.", id_counter);
    }
}

/**
 * @brief Wait until the head of the queue is due and return a copy of its agent id.
 *
 * The entry is NOT removed: it stays queued (and persisted) until the relay confirms the purge was
 * accepted, so a crash mid-request replays it instead of losing it.
 *
 * @return The agent id, owned by the caller, or NULL when the daemon is shutting down.
 */
char* purge_queue_peek_due(void) {
    char *agent_id = NULL;

    w_mutex_lock(&mutex_purge);

    while (!purge_stopping) {
        if (!purge_queue) {
            w_cond_wait(&cond_purge, &mutex_purge);
            continue;
        }

        const time_t now = w_get_monotonic_time();

        if (purge_queue->due_mono <= now) {
            os_strdup(purge_queue->id, agent_id);
            break;
        }

        // Not due yet: sleep until it is, or until a push or the shutdown wakes us earlier.
        struct timespec deadline = {0, 0};
#ifdef CLOCK_MONOTONIC
        clock_gettime(purge_cond_monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME, &deadline);
#else
        deadline.tv_sec = time(NULL);
#endif
        deadline.tv_sec += (purge_queue->due_mono - now);
        pthread_cond_timedwait(&cond_purge, &mutex_purge, &deadline);
    }

    w_mutex_unlock(&mutex_purge);
    return agent_id;
}

/**
 * @brief Drop the head after a successful relay, and persist the shorter queue.
 */
void purge_queue_drop_head(void) {
    purge_node_t *node;

    w_mutex_lock(&mutex_purge);

    node = purge_queue;
    if (node) {
        purge_queue = node->next;
        if (!purge_queue) {
            purge_tail = &purge_queue;
        }
        purge_queue_size--;
        purge_file_write_locked();
    }

    w_mutex_unlock(&mutex_purge);

    if (node) {
        os_free(node->id);
        os_free(node);
    }
}

/**
 * @brief Push the head's next attempt into the future after a failed relay.
 *
 * Kept rather than dropped: the entry is the only record that this agent's documents still have to
 * go, and the purge is idempotent, so retrying costs nothing but a little indexer work. The log is
 * throttled because a server that stays unreachable would otherwise print the same warning for the
 * same agent every delay.
 *
 * The deferred entry stays at the head, so anything queued behind it waits too. That is the right
 * trade here: every way this relay fails (an unreachable socket, a 503 while no indexer host is
 * healthy) is server-wide, so the entries behind it would fail as well -- and holding the order
 * keeps the retry from starving whoever is first in line.
 */
void purge_queue_defer_head(const char *agent_id) {
    unsigned int attempts = 0;
    time_t retry_in = 0;

    w_mutex_lock(&mutex_purge);

    if (purge_queue) {
        // The delay doubles as the retry interval: it is already the "come back later" this queue
        // is built around, and it keeps a stuck entry from spinning.
        retry_in = (config.purge_delay > 0) ? config.purge_delay : PURGE_RETRY_FLOOR_SECONDS;
        purge_queue->due_mono = w_get_monotonic_time() + retry_in;
        attempts = ++purge_queue->attempts;
        purge_file_write_locked();
    }

    w_mutex_unlock(&mutex_purge);

    if (attempts == 1) {
        mwarn("The deletion of agent '%s' could not be relayed to the inventory sync server; it stays "
              "queued and will be retried in %ld s.", agent_id, (long)retry_in);
    } else {
        mdebug1("The deletion of agent '%s' is still pending after %u attempt(s); next retry in %ld s.",
                agent_id, attempts, (long)retry_in);
    }
}

/**
 * @brief Load the deletions a previous run left behind, and arm them.
 *
 * Called from main() before the threads start, so nothing contends for the queue yet.
 *
 * Two rules that are not obvious:
 *   - A backward clock jump (now earlier than the file's own last_update) makes every stored
 *     timestamp untrustworthy, so they are all re-stamped to now: better to wait the full delay
 *     again than to fire a purge whose delay never actually elapsed.
 *   - Nothing is due before `purge_delay` from this very startup, even entries that are overdue on
 *     paper. Part of what the delay buys is cluster workers having pulled the new client.keys, and
 *     right after a restart they have not.
 */
void purge_file_load(void) {
    FILE *fp = wfopen(PENDING_PURGES_FILE, "r");
    char line[OS_BUFFER_SIZE];
    const time_t now = time(NULL);
    const time_t now_mono = w_get_monotonic_time();
    time_t last_update = 0;
    bool clock_went_back = false;
    unsigned int loaded = 0;

    if (!fp) {
        if (errno != ENOENT) {
            mwarn("Could not read '%s': %s. Deletions pending from the previous run, if any, will not "
                  "be retried.", PENDING_PURGES_FILE, strerror(errno));
        }
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char label[32] = {0};
        char id[32] = {0};
        long stamp = 0;

        if (sscanf(line, "%31s", label) != 1) {
            continue;
        }

        if (!strcmp(label, "last_update")) {
            if (sscanf(line, "%31s %ld", label, &stamp) == 2) {
                last_update = (time_t)stamp;
                clock_went_back = (now < last_update);
            }
            continue;
        }

        if (!strcmp(label, "last_id")) {
            int stored_id = 0;

            if (sscanf(line, "%31s %d", label, &stored_id) == 2 && stored_id > purge_last_id) {
                purge_last_id = stored_id;
            }
            continue;
        }

        if (strcmp(label, "purge")) {
            // Unknown label: ignored on purpose, so a newer format can add lines without this
            // parser rejecting a file it merely does not fully understand.
            mdebug2("Ignoring unknown entry '%s' in '%s'.", label, PENDING_PURGES_FILE);
            continue;
        }

        if (sscanf(line, "%31s %31s %ld", label, id, &stamp) != 3 || !OS_IsValidID(id)) {
            mwarn("Ignoring a malformed entry in '%s'.", PENDING_PURGES_FILE);
            continue;
        }

        purge_node_t *node;
        os_calloc(1, sizeof(purge_node_t), node);
        os_strdup(id, node->id);
        node->requested_at = clock_went_back ? now : (time_t)stamp;

        const time_t elapsed = (now > node->requested_at) ? (now - node->requested_at) : 0;
        const time_t remaining = (config.purge_delay > elapsed) ? (config.purge_delay - elapsed) : 0;
        const time_t grace = now_mono + config.purge_delay;

        node->due_mono = now_mono + remaining;
        if (node->due_mono < grace) {
            node->due_mono = grace;
        }

        (*purge_tail) = node;
        purge_tail = &node->next;
        purge_queue_size++;
        loaded++;
    }

    fclose(fp);

    if (clock_went_back) {
        mwarn("The system clock is earlier than the last update of '%s'; the %u pending deletion(s) were "
              "re-stamped so each one waits its full delay again.", PENDING_PURGES_FILE, loaded);
    }

    if (loaded > 0) {
        minfo("Recovered %u pending agent deletion(s) from '%s'; they will be relayed to the inventory "
              "sync server after %d s.", loaded, PENDING_PURGES_FILE, config.purge_delay);
    }

    /* The id counter never goes backwards. OS_ReadKeys() rebuilt it from client.keys, which no
     * longer lists the agents that were just deleted, so without this an id whose purge is still
     * pending could be handed to a new agent -- and the purge would wipe that agent's documents. */
    if (purge_last_id > keys.id_counter) {
        /* INFO, not debug: this is the line that explains why the next agent id "jumps", and it is
         * the visible trace of a data-integrity guard -- an id whose purge is still pending must
         * never be handed out again. It only prints when the counter actually had to be raised. */
        minfo("Raising the agent id counter from %d to %d: ids that were handed out are never reused.",
              keys.id_counter, purge_last_id);
        keys.id_counter = purge_last_id;
    } else if (keys.id_counter > purge_last_id) {
        purge_last_id = keys.id_counter;
    }
}

/**
 * @brief Report what the relay could not send before shutdown. Frees memory; keeps the file.
 *
 * The file is deliberately left alone: it IS the record that these deletions are still owed, and
 * the next start replays it. Saying the number out loud is what the previous behavior lacked --
 * pending deletions used to be dropped without a word.
 */
void purge_queue_discard(void) {
    unsigned int abandoned;
    purge_node_t *node;
    purge_node_t *next;

    w_mutex_lock(&mutex_purge);

    abandoned = purge_queue_size;
    node = purge_queue;
    purge_queue = NULL;
    purge_tail = &purge_queue;
    purge_queue_size = 0;

    // Reservations die with the process: they were never persisted, and the agents they refer to are
    // still in client.keys unless the writer got to them (in which case they are in `node` above).
    while (purge_reserved) {
        purge_reserved_t *stale = purge_reserved;
        purge_reserved = stale->next;
        os_free(stale->id);
        os_free(stale);
    }

    w_mutex_unlock(&mutex_purge);

    for (; node; node = next) {
        next = node->next;
        os_free(node->id);
        os_free(node);
    }

    if (abandoned > 0) {
        minfo("Shutting down with %u pending agent deletion(s); they stay recorded in '%s' and will be "
              "retried on the next start.", abandoned, PENDING_PURGES_FILE);
    }
}

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
#include "manager_task_op.h"
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

/* The handoff journal between phase 1 and phase 4 of a deletion. See auth.h for the phase list.
 *
 * Its own mutex, deliberately NOT mutex_keys: phase 0 runs on request threads and phases 1 and 4 on
 * the writer, so they must never contend for the lock the enrollment path also takes.
 *
 * Only agent ids travel here, so the memory cost is a few dozen bytes per entry. The cap is not
 * about memory: it bounds how many deletions can be in flight at once, and past it new deletions
 * are REFUSED AT THE REQUEST -- which is the whole point of moving that decision to phase 0. The
 * old code discovered the overflow after client.keys had been written, where the only options left
 * were to drop the purge silently or to log and orphan the documents. */
#define PURGE_QUEUE_MAX_ENTRIES 65536

typedef struct purge_node {
    char *id;
    /// Wall-clock second the deletion was requested. Persisted; it becomes the row's initial
    /// NEXT_ATTEMPT_AT offset, so authd.purge_delay survives a restart as the delay it always was.
    time_t requested_at;
    /// This entry's monotonic sequence. See purge_journal_entry_t.
    long long journal_seq;
    struct purge_node *next;
} purge_node_t;

static purge_node_t *purge_journal = NULL;
static purge_node_t **purge_journal_tail = &purge_journal;
static unsigned int purge_journal_size = 0;
static pthread_mutex_t mutex_purge = PTHREAD_MUTEX_INITIALIZER;
/// Highest agent id ever handed out, persisted alongside the journal. Guarded by mutex_purge.
static int purge_last_id = 0;
/// Highest journal sequence ever assigned, persisted. Guarded by mutex_purge. Never reused, never
/// reset: a repeat would make two genuinely different deletions of one agent derive one task id.
static long long purge_last_seq = 0;

/// Manager-task rows outstanding, as last measured by the writer. Guarded by mutex_purge rather
/// than made atomic: phase 0 already takes that lock for the journal and reservation counts, so one
/// lock covers all three terms and the check is consistent instead of three independent reads.
static int purge_pending_rows = 0;

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

/// Drop a reservation, with mutex_purge already held. Called at PHASE 1, and only there: the
/// journal is the durable record of the id from that point on, so the reservation covers exactly
/// the gap between the delete response and the journal line, with no instant uncovered.
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

/// How many ids are reserved. mutex_purge must be held.
static unsigned int purge_reserved_count_locked(void) {
    unsigned int count = 0;
    purge_reserved_t *node;

    for (node = purge_reserved; node; node = node->next) {
        count++;
    }

    return count;
}

/// Whether an id is in one of authd's OWN records of a deletion in flight -- journaled, or reserved
/// and not yet journaled. mutex_purge must be held. Both lists are bounded by the deletions between
/// phase 0 and phase 4, so this stays a short scan however long the process has been running.
static bool purge_in_flight_locked(const char *agent_id) {
    for (purge_node_t *node = purge_journal; node; node = node->next) {
        if (!strcmp(node->id, agent_id)) {
            return true;
        }
    }

    for (purge_reserved_t *reserved = purge_reserved; reserved; reserved = reserved->next) {
        if (!strcmp(reserved->id, agent_id)) {
            return true;
        }
    }

    return false;
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
        /* PHASE 0, on this path too. A replacement IS a deletion -- add_remove() and OS_DeleteKey()
         * are one line below -- and it is the higher-volume one: a mass re-enrollment produces one
         * per agent, where the local socket produces one per API call. Without this the journal and
         * the row backlog would grow past the bound that the delete path is refused against, and
         * past the point where anything can still be refused: one line down the agent is out of the
         * keystore and the enrollment has been answered.
         *
         * Refusing the ENROLLMENT is the whole point. The agent keeps its registration, the
         * enrolling one is told to come back, and nothing has been deleted that cannot be
         * recorded. */
        if (purge_backlog_full()) {
            snprintf(message, OS_SIZE_128, "Agent '%s' can't be replaced: too many deletions are in progress.",
                     key->id);
            os_strdup(message, *str_result);
            return OS_INVALID;
        }

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
 * @brief Persist the journal. The caller MUST hold mutex_purge.
 *
 * Rewrites the whole file into a temporary and renames it over the target, the same way
 * OS_WriteKeys() persists client.keys: a partial write can then never be observed, and the file is
 * small enough -- normally empty -- that rewriting it beats maintaining tombstones.
 */
static void purge_file_write_locked(void) {
    File file;
    purge_node_t *node;

    if (TempFile(&file, PENDING_PURGES_FILE, 0) < 0) {
        mwarn("Could not open a temporary file for '%s': %s. The deletions in progress are still "
              "recorded in memory, but a crash would lose the record.",
              PENDING_PURGES_FILE, strerror(errno));
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

    /* The sequence high-water mark, for the same reason and with a stricter rule: it must never go
     * backwards even by one, or a later deletion of an already-deleted agent would derive a task id
     * that a row in the retention window already holds, and the create would report `collided` --
     * which phase 3 reads as "already recorded" and would silently swallow a real deletion. */
    if (fprintf(file.fp, "last_seq %lld\n", purge_last_seq) < 0) {
        goto error;
    }

    for (node = purge_journal; node; node = node->next) {
        if (fprintf(file.fp, "purge %s %ld %lld\n", node->id, (long)node->requested_at, node->journal_seq) < 0) {
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
    mwarn("Could not write '%s'. The deletions in progress are still recorded in memory, but a "
          "crash would lose the record.", PENDING_PURGES_FILE);
    unlink(file.name);
    os_free(file.name);
}

/**
 * @brief Phase 0: whether another deletion may be admitted right now.
 *
 * Two terms, and both are needed:
 *
 *   - `journal length + reservations >= PURGE_QUEUE_MAX_ENTRIES`. NOT the journal alone. This runs
 *     on the request thread while phase 1 appends at writer time, so a burst would each see "not
 *     full", all pass, and phase 1 would overflow where refusal is no longer possible.
 *     `purge_reserved` IS the admitted-but-not-yet-journaled set, which is exactly the gap.
 *   - the manager-task backlog. The journal bounds admission-in-flight, not row count; rows
 *     accumulate independently, and the retention ceiling only evicts TERMINAL rows while these are
 *     pending. The writer refreshes this once per cycle -- one query per cycle, not per agent.
 *
 * The second term FAILS OPEN by construction: a failed measurement keeps the previous value (see
 * purge_pending_rows_update), because a wazuh-db outage must not block agent deletion. During such
 * an outage the journal term is the only live bound, which is what it is sized for.
 */
bool purge_backlog_full(void) {
    bool full = false;
    unsigned int in_flight;

    w_mutex_lock(&mutex_purge);

    in_flight = purge_journal_size + purge_reserved_count_locked();

    if (in_flight >= PURGE_QUEUE_MAX_ENTRIES) {
        full = true;
        mwarn("Refusing the deletion: %u are already in progress, the limit being %d. Retry once "
              "they have been recorded.", in_flight, PURGE_QUEUE_MAX_ENTRIES);
    } else if (config.max_pending_deletes > 0 && purge_pending_rows >= config.max_pending_deletes) {
        full = true;
        mwarn("Refusing the deletion: %d agent deletions are still waiting to be applied to the "
              "indexer, the limit being %d. Retry once the backlog drains.",
              purge_pending_rows, config.max_pending_deletes);
    }

    w_mutex_unlock(&mutex_purge);

    return full;
}

/**
 * @brief Publish the backlog depth measured by the writer.
 *
 * A negative value means the measurement failed and the previous one stands. Reporting a failure as
 * zero would lift phase 0's second bound for exactly as long as wazuh-db is unreachable -- which is
 * when the backlog is least likely to be draining.
 */
void purge_pending_rows_update(int rows) {
    if (rows < 0) {
        return;
    }

    w_mutex_lock(&mutex_purge);
    purge_pending_rows = rows;
    w_mutex_unlock(&mutex_purge);
}

/**
 * @brief Phase 1: journal the intent to delete these agents, before client.keys is rewritten.
 *
 * Local only: a temp file and a rename. Writing the manager-task rows here instead would put a
 * wazuh-db round trip in front of every client.keys write, so an outage would block enrollment --
 * the very wedge this design exists to remove.
 *
 * The persist failing is not an error worth aborting on: the entries are in memory, phases 3 and 4
 * still run, and the only thing lost is the ability to recover from a crash in the next few
 * milliseconds. purge_file_write_locked() has already warned.
 */
purge_journal_entry_t* purge_journal_append(char **ids, size_t count) {
    purge_journal_entry_t *entries = NULL;
    size_t i;

    if (!ids || count == 0) {
        return NULL;
    }

    os_calloc(count, sizeof(purge_journal_entry_t), entries);

    w_mutex_lock(&mutex_purge);

    for (i = 0; i < count; i++) {
        purge_node_t *node;

        os_calloc(1, sizeof(purge_node_t), node);
        os_strdup(ids[i], node->id);
        node->requested_at = time(NULL);
        node->journal_seq = ++purge_last_seq;

        (*purge_journal_tail) = node;
        purge_journal_tail = &node->next;
        purge_journal_size++;

        strncpy(entries[i].id, node->id, sizeof(entries[i].id) - 1);
        entries[i].requested_at = node->requested_at;
        entries[i].journal_seq = node->journal_seq;

        // The journal is the durable owner of this id from here on, and it is what answers
        // purge_is_pending() from memory until phase 4 drops the line.
        purge_unreserve_id_locked(node->id);
    }

    purge_file_write_locked();

    w_mutex_unlock(&mutex_purge);

    return entries;
}

/**
 * @brief Phase 4: forget entries whose rows wazuh-db has acknowledged as durable.
 *
 * Only called on that acknowledgement. Dropping a line on anything weaker would leave a window in
 * which wazuh-db's death loses the row AND the record that it was owed -- which is why create
 * commits inside its own command rather than riding the deferred transaction.
 */
void purge_journal_drop(const purge_journal_entry_t *entries, size_t count) {
    size_t i;
    bool changed = false;

    if (!entries || count == 0) {
        return;
    }

    w_mutex_lock(&mutex_purge);

    for (i = 0; i < count; i++) {
        purge_node_t **prev;
        purge_node_t *node;

        for (prev = &purge_journal; (node = *prev) != NULL; prev = &node->next) {
            // Matched on the SEQUENCE, not the id: one agent can hold two journal lines at once
            // (deleted, re-enrolled, deleted again inside one writer cycle), and dropping by id
            // would forget the wrong one and leave the other owed forever.
            if (node->journal_seq == entries[i].journal_seq) {
                *prev = node->next;
                if (!*prev) {
                    purge_journal_tail = prev;
                }
                purge_journal_size--;
                changed = true;
                os_free(node->id);
                os_free(node);
                break;
            }
        }
    }

    if (changed) {
        purge_file_write_locked();
    }

    w_mutex_unlock(&mutex_purge);
}

/**
 * @brief Startup reconciliation: decide what each surviving journal line means.
 *
 * Called after OS_ReadKeys() and before any thread starts, so nothing contends for either
 * structure. Every crash point in the phase sequence resolves here:
 *
 *   | crashed          | line | client.keys | resolves to                                    |
 *   | before phase 1   | no   | present     | nothing owed                                   |
 *   | between 1 and 2  | yes  | PRESENT     | drop the line; the agent is alive              |
 *   | OS_WriteKeys err | yes  | PRESENT     | drop the line; phase 3 was correctly skipped   |
 *   | between 2 and 3  | yes  | gone        | CREATE the row -- the window this design closes|
 *   | between 3 and 4  | yes  | gone        | create again; the id collides, which is success|
 *   | after phase 4    | no   | gone        | the row is already committed                   |
 *
 * Rows two and three are indistinguishable from here and resolve identically, which is why the
 * gate on OS_WriteKeys needs no separate record: an agent still in client.keys was never deleted,
 * whichever of the two happened.
 *
 * The kept lines stay journaled until phase 3 records them, so an explicit-id insert naming one of
 * them is refused from memory in the meantime.
 */
purge_journal_entry_t* purge_journal_snapshot(size_t *count) {
    purge_journal_entry_t *owed = NULL;
    purge_node_t *node;
    size_t i = 0;

    if (count) {
        *count = 0;
    }

    w_mutex_lock(&mutex_purge);

    if (purge_journal_size > 0) {
        os_calloc(purge_journal_size, sizeof(purge_journal_entry_t), owed);

        for (node = purge_journal; node && i < purge_journal_size; node = node->next, i++) {
            strncpy(owed[i].id, node->id, sizeof(owed[i].id) - 1);
            owed[i].requested_at = node->requested_at;
            owed[i].journal_seq = node->journal_seq;
        }
    }

    w_mutex_unlock(&mutex_purge);

    if (count) {
        *count = i;
    }

    return owed;
}

purge_journal_entry_t* purge_journal_reconcile(size_t *count) {
    purge_journal_entry_t *owed = NULL;
    purge_node_t **prev;
    purge_node_t *node;
    size_t kept = 0;
    unsigned int dropped = 0;
    bool changed = false;

    if (count) {
        *count = 0;
    }

    w_mutex_lock(&mutex_purge);

    for (prev = &purge_journal; (node = *prev) != NULL;) {
        if (OS_IsAllowedID(&keys, node->id) >= 0) {
            // Still on disk, so the deletion never became final. Nothing is owed for it, and the
            // agent keeps its id.
            *prev = node->next;
            if (!*prev) {
                purge_journal_tail = prev;
            }
            purge_journal_size--;
            dropped++;
            changed = true;
            os_free(node->id);
            os_free(node);
            continue;
        }

        kept++;
        prev = &node->next;
    }

    if (kept > 0) {
        size_t i = 0;

        os_calloc(kept, sizeof(purge_journal_entry_t), owed);

        for (node = purge_journal; node && i < kept; node = node->next, i++) {
            strncpy(owed[i].id, node->id, sizeof(owed[i].id) - 1);
            owed[i].requested_at = node->requested_at;
            owed[i].journal_seq = node->journal_seq;
        }
    }

    if (changed) {
        purge_file_write_locked();
    }

    w_mutex_unlock(&mutex_purge);

    if (dropped > 0) {
        minfo("Dropped %u journaled deletion(s) whose agents are still listed in client.keys: those "
              "deletions never completed, so nothing is owed for them.", dropped);
    }

    if (kept > 0) {
        minfo("Recovered %zu agent deletion(s) that were interrupted before being recorded; their "
              "tasks are being created now.", kept);
    }

    if (count) {
        *count = kept;
    }

    return owed;
}

bool purge_is_pending_locally(const char *agent_id) {
    bool in_flight;

    if (!agent_id) {
        return false;
    }

    w_mutex_lock(&mutex_purge);
    in_flight = purge_in_flight_locked(agent_id);
    w_mutex_unlock(&mutex_purge);

    return in_flight;
}

/**
 * @brief Whether this id still owes a purge.
 *
 * Handing such an id to a new agent would let the pending purge delete the NEW agent's documents:
 * the purge matches by agent id, and nothing in a state document distinguishes one owner from the
 * next (there is no timestamp, and two of the three indices in the scope carry no agent name).
 *
 * Three rules:
 *
 *   - IN FLIGHT here -> pending, from memory. The journal and the reservations are authd's own
 *     records and need no confirmation: the row for them either does not exist yet or was created
 *     moments ago.
 *   - Otherwise -> ASK THE ROW, which is the only authority on a deletion authd has already handed
 *     off. There is deliberately no local mirror of the outstanding rows in front of this query: a
 *     set that authd adds to at phase 1 and can only shrink when someone happens to look up that
 *     exact id grows without bound on a manager that churns agents, and every phase 1 then scans it
 *     under mutex_purge. The query costs one wazuh-db round trip on a path that is only reached by
 *     an insertion naming an explicit id.
 *   - Query FAILED -> pending. Refusing reuse is an error an operator can work around; allowing it
 *     risks an outstanding purge deleting a new agent's documents.
 *
 * It may block for up to authd.wdb_timeout, so it must NOT be called with mutex_keys held; see
 * local_add(), which is why purge_is_pending_locally() exists.
 */
bool purge_is_pending(const char *agent_id) {
    int status;

    if (!agent_id) {
        return false;
    }

    if (purge_is_pending_locally(agent_id)) {
        return true;
    }

    // A private socket rather than a shared one: this runs on whichever request thread is serving
    // the insertion.
    status = manager_task_agent_status(agent_id, MANAGER_TASK_TYPE_AGENT_DELETE, config.wdb_timeout);

    if (status == MANAGER_TASK_STATUS_FAILED) {
        mwarn("Could not check whether agent ID '%s' still owes a deletion; treating it as pending.",
              agent_id);
        return true;
    }

    // NONE as well as TERMINAL is free. Absent is reachable rather than hypothetical: OS_WriteKeys
    // fails, phase 3 is correctly skipped, and reconciliation drops the line without creating a row.
    return status == MANAGER_TASK_STATUS_OUTSTANDING;
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
 * @brief Load the journal a previous run left behind.
 *
 * Called from main() before the threads start, so nothing contends for it. Two rules that are not
 * obvious:
 *
 *   - A backward clock jump (now earlier than the file's own last_update) makes every stored
 *     timestamp untrustworthy, so they are all re-stamped to now: better to make a purge wait its
 *     full delay again than to run one whose delay never actually elapsed.
 *   - ENTRIES WITHOUT A SEQUENCE ARE NUMBERED BY POSITION, not handed the next value from
 *     last_seq. Position is deterministic across a crash during the conversion; a running counter
 *     is not, and re-assigning different sequences would derive different task ids and produce
 *     duplicate rows for one deletion -- breaking "a collision means already recorded" on precisely
 *     the path that story exists for.
 */
void purge_file_load(void) {
    FILE *fp = wfopen(PENDING_PURGES_FILE, "r");
    char line[OS_BUFFER_SIZE];
    const time_t now = time(NULL);
    time_t last_update = 0;
    bool clock_went_back = false;
    unsigned int loaded = 0;
    unsigned int converted = 0;
    long long position = 0;

    if (!fp) {
        if (errno != ENOENT) {
            mwarn("Could not read '%s': %s. Deletions interrupted by the previous run, if any, will "
                  "not be recovered.", PENDING_PURGES_FILE, strerror(errno));
        }
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char label[32] = {0};
        char id[32] = {0};
        long stamp = 0;
        long long seq = 0;
        int fields;

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

        if (!strcmp(label, "last_seq")) {
            long long stored_seq = 0;

            if (sscanf(line, "%31s %lld", label, &stored_seq) == 2 && stored_seq > purge_last_seq) {
                purge_last_seq = stored_seq;
            }
            continue;
        }

        if (strcmp(label, "purge")) {
            // Unknown label: ignored on purpose, so a newer format can add lines without this
            // parser rejecting a file it merely does not fully understand.
            mdebug2("Ignoring unknown entry '%s' in '%s'.", label, PENDING_PURGES_FILE);
            continue;
        }

        position++;

        fields = sscanf(line, "%31s %31s %ld %lld", label, id, &stamp, &seq);

        if (fields < 3 || !OS_IsValidID(id)) {
            mwarn("Ignoring a malformed entry in '%s'.", PENDING_PURGES_FILE);
            continue;
        }

        if (fields == 3) {
            // A file written by a release that had no sequences. By POSITION, deliberately -- see
            // the note above.
            seq = position;
            converted++;
        }

        purge_node_t *node;
        os_calloc(1, sizeof(purge_node_t), node);
        os_strdup(id, node->id);
        node->requested_at = clock_went_back ? now : (time_t)stamp;
        node->journal_seq = seq;

        if (seq > purge_last_seq) {
            purge_last_seq = seq;
        }

        (*purge_journal_tail) = node;
        purge_journal_tail = &node->next;
        purge_journal_size++;
        loaded++;
    }

    fclose(fp);

    if (clock_went_back) {
        mwarn("The system clock is earlier than the last update of '%s'; the %u recovered deletion(s) "
              "were re-stamped so each one waits its full delay again.", PENDING_PURGES_FILE, loaded);
    }

    if (converted > 0) {
        minfo("Converted %u deletion(s) from the previous file format in '%s'; they were numbered by "
              "position.", converted, PENDING_PURGES_FILE);
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
 * @brief Report what was still in the journal at shutdown. Frees memory; keeps the file.
 *
 * The file is deliberately left alone: it IS the record that these deletions are still owed, and
 * the next start reconciles it against client.keys.
 */
void purge_journal_discard(void) {
    unsigned int abandoned;
    purge_node_t *node;
    purge_node_t *next;

    w_mutex_lock(&mutex_purge);

    abandoned = purge_journal_size;
    node = purge_journal;
    purge_journal = NULL;
    purge_journal_tail = &purge_journal;
    purge_journal_size = 0;

    // Reservations die with the process: they were never persisted, and the agents they refer to
    // are still in client.keys unless the writer got to them (in which case they are journaled).
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
        minfo("Shutting down with %u agent deletion(s) still being recorded; they stay in '%s' and "
              "are reconciled on the next start.", abandoned, PENDING_PURGES_FILE);
    }
}

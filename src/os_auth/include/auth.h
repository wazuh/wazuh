/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#ifndef AUTHD_H
#define AUTHD_H

#ifndef ARGV0
#define ARGV0 "wazuh-authd"
#endif

#include "os_net.h"
#include "authd-config.h"
#include <pthread.h>
#include "ssl_op.h"
#include "sec.h"
#include "md5_op.h"
#include "sha1_op.h"

#define DEFAULT_PORT 1515
#define DEFAULT_CENTRALIZED_GROUP "default"
#define MAX_SSL_MSG_SIZE (OS_SIZE_65536 + OS_SIZE_4096)
#define SERVER_INDEX 0
#define STOP_FD (AUTH_POOL+1)

#define full(i, j) ((i + 1) % AUTH_POOL == j)
#define empty(i, j) (i == j)
#define forward(x) x = (x + 1) % AUTH_POOL

struct client {
    int socket;
    int index;
    union {
        struct in_addr *addr4;
        struct in6_addr *addr6;
    };
    bool is_ipv6;
    SSL *ssl;
    bool handshake_done;
    bool enrollment_ok;
    char ip[IPSIZE + 1];

    char* read_buffer;
    int  read_offset;

    char* write_buffer;
    int  write_offset;
    int  write_len;

    char* agentname;
    char* centralized_group;
    char* new_id;
};

struct keynode {
    char *id;
    char *name;
    char *ip;
    char *group;
    char *raw_key;
    struct keynode *next;
};

// Thread for internal server
void* run_local_server(void *arg);

// Append key to insertion queue
void add_insert(const keyentry *entry,const char *group);

// Append key to deletion queue
void add_remove(const keyentry *entry);

// Read configuration
int authd_read_config(const char *path);
cJSON *getAuthdConfig(void);
size_t authcom_dispatch(const char * command, char ** output);
size_t authcom_getconfig(const char * section, char ** output);

// Block signals
void authd_sigblock();

/**
 * @brief Validate if groups are valid for new enrollment
 * @param groups Comma separated string with new enrollment groups
 * @param response 2048 length buffer where the error response will be copied. NULL if no response is required
 * */
w_err_t w_auth_validate_groups(const char *groups, char *response);

/**
 * @brief Cleanup compiled regex for group validation (for testing)
 * */
void w_auth_validate_groups_cleanup(void);

/**
 * @brief Parse a raw buffer from agent request into enrollment data.
 * @param buf Raw buffer to be parsed
 * @param response 2048 length buffer where the error response will be copied
 * @param authpass Authentication password expected on the buffer, NULL if there isn't password
 * @param ip IP direction of the request. Can be override with IP parsed from buffer
 * @param agentname Pointer where parsed agent name will be allocated
 * @param groups Pointer where parsed groups will be allocated
 * @param key_hash Pointer where parsed key hash will be allocated
 * */
w_err_t w_auth_parse_data(const char* buf,
                          char *response,
                          const char *authpass,
                          char *ip,
                          char **agentname,
                          char **groups,
                          char **key_hash);

/**
 * @brief Validates if new enrollment is possible with provided data.
 * With force configuration disabled, if enrollment data is already registered, validation will fail.
 * With force configuration enabled, duplicated entry will be removed.
 * @param response 2048 length buffer where the error response will be copied
 * @param ip New enrollment ip direction
 * @param agentname New enrollment agent name
 * @param groups New enrollment groups
 * @param hash_key Hash of the key on the agent
 * */
w_err_t w_auth_validate_data(char *response,
                             const char *ip,
                             const char *agentname,
                             const char *groups,
                             const char *hash_key);

/**
 * @brief Validates if the old agent can be replaced and removes it.
 * @param key Key structure of the agent to be removed
 * @param hash_key Hash of the key on the agent
 * @param force_options Force configuration structure to define how the agent replacement must be handled.
 * @param str_result A message related to the result of the agent replacement. Must be freed by the caller.
 * @param warn Set to true when the rejection reflects a live identity conflict (the existing agent is still connected and does not self-heal); false for transient or expected rejections. May be NULL.
 * */
w_err_t w_auth_replace_agent(keyentry *key,
                             const char *key_hash,
                             authd_force_options_t *force_options,
                             char** str_result,
                             bool *warn);

/**
 * @brief Adds new agent with provided enrollment data.
 * @param response 2048 length buffer where the error response will be copied
 * @param ip New enrollment ip direction
 * @param agentname New enrollment agent name
 * @param id Pointer where new Agent ID will be allocated
 * @param key Pointer where new Agent key will be allocated
 * */
w_err_t w_auth_add_agent(char *response,
                         const char *ip,
                         const char *agentname,
                         char **id,
                         char **key);

/**
 * @brief Adds new agent from a local request
 * @param id Agent ID of the agent to be registered
 * @param ip Agent IP of the agent to be registered
 * @param groups Groups to which the agent belongs
 * @param key Agent key if was already registered
 * @param key_hash Hash of the agent key
 * @param force_options Options to decide if forcing the insertion
 * @return JSON object with the response
 * */
cJSON* local_add(const char *id,
                        const char *name,
                        const char *ip,
                        const char *groups,
                        const char *key,
                        const char *key_hash,
                        authd_force_options_t *force_options);

/**
 * @brief Forwards an "add" request to the master node over the cluster (worker nodes only).
 *        Any caller-supplied id/key/force are ignored -- the master always assigns the ID,
 *        generates the key, and decides force-replace using its own configuration, matching
 *        the network (port 1515) enrollment path's worker behavior.
 * @param name Name of the agent to be registered
 * @param ip IP of the agent to be registered
 * @param groups Groups to which the agent belongs
 * @param key_hash Hash of the agent key, used for the force/key-mismatch decision
 * @return JSON object with the response
 * */
cJSON* local_add_clustered(const char *name,
                           const char *ip,
                           const char *groups,
                           const char *key_hash);

/**
 * @brief Returns a MD5 hash of some random data collected from different sources.
 *        The result must be freed by the caller.
 *
 * @return const char* The resulting hash or NULL on error.
 */
char *w_generate_random_pass();

/* Load the shared password (master): read it from @p path or generate+persist one.
 * Fail-closed on an invalid existing file; never returns NULL. Sets @p generated. */
char *w_authd_load_password(const char *path, bool *generated);

/* Read the shared password from @p path (cluster worker): never generates, persists,
 * nor exits. Returns NULL when missing/empty/short/unreadable. */
char *w_authd_read_password(const char *path);

extern char shost[512];
extern keystore keys;
extern volatile int write_pending;
/* --- The agent-deletion handoff journal --------------------------------------------------------
 *
 * PENDING_PURGES_FILE is no longer a queue with its own scheduler and retry ladder. It is a HANDOFF
 * JOURNAL holding only the ids currently between phase 1 and phase 4 of a deletion, and it is
 * normally empty: it drains at wazuh-db speed rather than at indexer speed. The purge itself is a
 * manager-task row, executed by the Task Manager's dispatcher, and authd's whole responsibility is
 * to make sure that row exists.
 *
 * The phases, in the order they run:
 *
 *   0. ADMIT OR REFUSE, on the REQUEST thread, before OS_DeleteKey -- purge_backlog_full(). It has
 *      to be here: by phase 1 the agent is already out of the in-memory keystore and the caller has
 *      already been told the deletion succeeded, so there is nothing left to refuse and nobody to
 *      tell. This is the one phase that can say no. BOTH paths that delete an agent take it -- the
 *      local socket's remove, and a force replacement, which is a deletion in every other respect
 *      and the higher-volume one.
 *   1. INTENT, before OS_WriteKeys -- purge_journal_append(). A local file write, no external
 *      dependency, so an outage anywhere else cannot block a client.keys write.
 *   2. OS_WriteKeys. The point of no return, and its RETURN VALUE IS CAPTURED.
 *   3. CREATE, only if step 2 succeeded. One row per id over the writer's own wazuh-db socket.
 *      Create commits inside its own command, so that `ok` is the durability acknowledgement.
 *   4. FORGET, on that ok -- purge_journal_drop().
 *
 * Gating 3 on 2 is load-bearing: the writer LOGS a failed OS_WriteKeys and falls through to the
 * removal loop, so without the gate authd would create purge rows for agents still on disk.
 *
 * A crash anywhere in that sequence is resolved at the next start by purge_journal_reconcile(),
 * which compares each line against the client.keys it has just read.
 */

/// One journaled deletion: the agent, when it was requested, and its sequence.
typedef struct purge_journal_entry_t {
    char id[16];
    time_t requested_at;
    /// Monotonic per-entry sequence, persisted. It is what makes the task id of a deletion
    /// derivable twice (phase 3 and reconciliation) without a second genuine deletion of the same
    /// agent colliding with the first -- which a wall-clock stamp could not promise.
    long long journal_seq;
} purge_journal_entry_t;

/// Recover the journal a previous run left behind, and raise the id counter past every id it
/// mentions. Call after OS_ReadKeys() and before any thread starts.
void purge_file_load(void);

/// Phase 0. Whether the deletion backlog is too deep to admit another one. Called on the request
/// thread; both of its terms are described at the definition.
bool purge_backlog_full(void);

/// Phase 1. Append @p count ids to the journal, assigning each the next sequence, and persist it.
/// Releases each id's removal-time reservation as the journal takes over as the durable record, so
/// an id is covered continuously from admission onwards.
///
/// @return A caller-owned array of @p count entries as journaled, or NULL when @p count is 0.
purge_journal_entry_t* purge_journal_append(char **ids, size_t count);

/// Phase 4. Drop these entries from the journal and persist the shorter file.
void purge_journal_drop(const purge_journal_entry_t *entries, size_t count);

/// Startup reconciliation. For every journaled line, consult the client.keys already read: an
/// agent still listed there means the deletion never became final, so the line is dropped; an
/// absent one means phase 2 completed and the row is still owed.
///
/// @param[out] count Entries still owed.
/// @return A caller-owned array of them, or NULL when nothing is owed.
purge_journal_entry_t* purge_journal_reconcile(size_t *count);

/// Whether an id still owes a purge, so it must not be handed to a new agent. Answers from memory
/// when authd is still holding the deletion itself, and otherwise ASKS THE ROW, which is the only
/// authority once the deletion has been handed off. Fails closed.
///
/// BLOCKS for up to authd.wdb_timeout, so it must not be called with mutex_keys held.
bool purge_is_pending(const char *agent_id);

/// The memory-only half of purge_is_pending(): whether the id is journaled or reserved here, which
/// is what authd knows without asking anyone. Never blocks, so it is the one that may be called
/// under mutex_keys -- as a re-check, after purge_is_pending() has already answered outside it.
bool purge_is_pending_locally(const char *agent_id);

/// Publish the manager-task backlog depth the writer measured, for phase 0's second term. Failing
/// to measure it must NOT be reported as zero: keep the last value instead, or a wazuh-db outage
/// would silently lift the bound.
void purge_pending_rows_update(int rows);

/// Record the highest id handed out so far, so it is never reused after a restart.
void purge_last_id_update(int id_counter);

/// Free the in-memory journal at shutdown and report what is still owed. The file is kept.
void purge_journal_discard(void);

extern volatile int running;
extern pthread_mutex_t mutex_keys;
extern pthread_cond_t cond_pending;
extern authd_config_t config;

#endif /* AUTHD_H */

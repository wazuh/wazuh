/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_H
#define WDB_H

#include <shared.h>
#include <pthread.h>
#include <openssl/evp.h>
#include "external/sqlite/sqlite3.h"
#include "syscheck_op.h"
#include "rootcheck_op.h"
#include "wazuhdb_op.h"

#define WDB_AGENT_EMPTY 0
#define WDB_AGENT_PENDING 1
#define WDB_AGENT_UPDATED 2

#define WDB_FILE_TYPE_FILE 0
#define WDB_FILE_TYPE_REGISTRY 1

#define WDB_FIM_NOT_FOUND 0
#define WDB_FIM_ADDED 1
#define WDB_FIM_MODIFIED 2
#define WDB_FIM_READDED 3
#define WDB_FIM_DELETED 4

#define WDB_GROUPS 0
#define WDB_SHARED_GROUPS 1
#define WDB_NETADDR_IPV4 0

#define WDB_MULTI_GROUP_DELIM '-'

#define WDB_RESPONSE_BEGIN_SIZE 16

#define WDB_DATABASE_LOGTAG ARGV0 ":wdb_agent"

#define WDB_MAX_COMMAND_SIZE    512
#define WDB_MAX_RESPONSE_SIZE   OS_MAXSTR-WDB_MAX_COMMAND_SIZE

typedef enum wdb_stmt {
    WDB_STMT_FIM_LOAD,
    WDB_STMT_FIM_FIND_ENTRY,
    WDB_STMT_FIM_INSERT_ENTRY,
    WDB_STMT_FIM_INSERT_ENTRY2,
    WDB_STMT_FIM_UPDATE_ENTRY,
    WDB_STMT_FIM_DELETE,
    WDB_STMT_FIM_UPDATE_DATE,
    WDB_STMT_FIM_FIND_DATE_ENTRIES,
    WDB_STMT_FIM_GET_ATTRIBUTES,
    WDB_STMT_FIM_UPDATE_ATTRIBUTES,
    WDB_STMT_OSINFO_INSERT,
    WDB_STMT_OSINFO_DEL,
    WDB_STMT_PROGRAM_INSERT,
    WDB_STMT_PROGRAM_DEL,
    WDB_STMT_PROGRAM_UPD,
    WDB_STMT_PROGRAM_GET,
    WDB_STMT_HWINFO_INSERT,
    WDB_STMT_HOTFIX_INSERT,
    WDB_STMT_HWINFO_DEL,
    WDB_STMT_HOTFIX_DEL,
    WDB_STMT_SET_HOTFIX_MET,
    WDB_STMT_PORT_INSERT,
    WDB_STMT_PORT_DEL,
    WDB_STMT_PROC_INSERT,
    WDB_STMT_PROC_DEL,
    WDB_STMT_NETINFO_INSERT,
    WDB_STMT_PROTO_INSERT,
    WDB_STMT_ADDR_INSERT,
    WDB_STMT_NETINFO_DEL,
    WDB_STMT_PROTO_DEL,
    WDB_STMT_ADDR_DEL,
    WDB_STMT_CISCAT_INSERT,
    WDB_STMT_CISCAT_DEL,
    WDB_STMT_SCAN_INFO_UPDATEFS,
    WDB_STMT_SCAN_INFO_UPDATEFE,
    WDB_STMT_SCAN_INFO_UPDATESS,
    WDB_STMT_SCAN_INFO_UPDATEES,
    WDB_STMT_SCAN_INFO_UPDATE1C,
    WDB_STMT_SCAN_INFO_UPDATE2C,
    WDB_STMT_SCAN_INFO_UPDATE3C,
    WDB_STMT_SCAN_INFO_GETFS,
    WDB_STMT_SCAN_INFO_GETFE,
    WDB_STMT_SCAN_INFO_GETSS,
    WDB_STMT_SCAN_INFO_GETES,
    WDB_STMT_SCAN_INFO_GET1C,
    WDB_STMT_SCAN_INFO_GET2C,
    WDB_STMT_SCAN_INFO_GET3C,
    WDB_STMT_SCA_FIND,
    WDB_STMT_SCA_UPDATE,
    WDB_STMT_SCA_INSERT,
    WDB_STMT_SCA_SCAN_INFO_INSERT,
    WDB_STMT_SCA_SCAN_INFO_UPDATE,
    WDB_STMT_SCA_INSERT_COMPLIANCE,
    WDB_STMT_SCA_INSERT_RULES,
    WDB_STMT_SCA_FIND_SCAN,
    WDB_STMT_SCA_SCAN_INFO_UPDATE_START,
    WDB_STMT_SCA_POLICY_FIND,
    WDB_STMT_SCA_POLICY_SHA256,
    WDB_STMT_SCA_POLICY_INSERT,
    WDB_STMT_SCA_CHECK_GET_ALL_RESULTS,
    WDB_STMT_SCA_POLICY_GET_ALL,
    WDB_STMT_SCA_POLICY_DELETE,
    WDB_STMT_SCA_CHECK_DELETE,
    WDB_STMT_SCA_SCAN_INFO_DELETE,
    WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE,
    WDB_STMT_SCA_CHECK_RULES_DELETE,
    WDB_STMT_SCA_CHECK_FIND,
    WDB_STMT_SCA_CHECK_DELETE_DISTINCT,
    WDB_STMT_FIM_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_DELETE_AROUND,
    WDB_STMT_FIM_DELETE_RANGE,
    WDB_STMT_FIM_CLEAR,
    WDB_STMT_SYNC_UPDATE_ATTEMPT,
    WDB_STMT_SYNC_UPDATE_COMPLETION,
    WDB_STMT_MITRE_NAME_GET,
    WDB_STMT_ROOTCHECK_INSERT_PM,
    WDB_STMT_ROOTCHECK_UPDATE_PM,
    WDB_STMT_ROOTCHECK_DELETE_PM,
    WDB_STMT_GLOBAL_INSERT_AGENT,
    WDB_STMT_GLOBAL_UPDATE_AGENT_NAME,
    WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION,
    WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP,
    WDB_STMT_GLOBAL_LABELS_GET,
    WDB_STMT_GLOBAL_LABELS_DEL,
    WDB_STMT_GLOBAL_LABELS_SET,
    WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE,
    WDB_STMT_GLOBAL_DELETE_AGENT,
    WDB_STMT_GLOBAL_SELECT_AGENT_NAME,
    WDB_STMT_GLOBAL_SELECT_AGENT_GROUP,
    WDB_STMT_GLOBAL_FIND_AGENT,
    WDB_STMT_GLOBAL_SELECT_AGENT_STATUS,
    WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS,
    WDB_STMT_GLOBAL_FIND_GROUP,
    WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP,
    WDB_STMT_GLOBAL_INSERT_AGENT_GROUP,
    WDB_STMT_GLOBAL_INSERT_AGENT_BELONG,
    WDB_STMT_GLOBAL_DELETE_AGENT_BELONG,
    WDB_STMT_GLOBAL_DELETE_GROUP_BELONG,
    WDB_STMT_GLOBAL_DELETE_GROUP,
    WDB_STMT_GLOBAL_SELECT_GROUPS,
    WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE,
    WDB_STMT_GLOBAL_SYNC_REQ_GET,
    WDB_STMT_GLOBAL_SYNC_SET,
    WDB_STMT_GLOBAL_UPDATE_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_AGENTS,
    WDB_STMT_GLOBAL_GET_AGENTS_BY_GREATER_KEEPALIVE,
    WDB_STMT_GLOBAL_GET_AGENTS_BY_LESS_KEEPALIVE,
    WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE,
    WDB_STMT_PRAGMA_JOURNAL_WAL,
    WDB_STMT_SIZE // This must be the last constant
} wdb_stmt;

typedef enum global_db_access {
    WDB_INSERT_AGENT,
    WDB_INSERT_AGENT_GROUP,
    WDB_INSERT_AGENT_BELONG,
    WDB_UPDATE_AGENT_NAME,
    WDB_UPDATE_AGENT_DATA,
    WDB_UPDATE_AGENT_KEEPALIVE,
    WDB_UPDATE_AGENT_STATUS,
    WDB_UPDATE_AGENT_GROUP,
    WDB_SET_AGENT_LABELS,
    WDB_GET_ALL_AGENTS,
    WDB_GET_AGENTS_BY_KEEPALIVE,
    WDB_FIND_AGENT,
    WDB_GET_AGENT_INFO,
    WDB_GET_AGENT_LABELS,
    WDB_SELECT_AGENT_NAME,
    WDB_SELECT_AGENT_GROUP,
    WDB_SELECT_AGENT_STATUS,
    WDB_SELECT_KEEPALIVE,
    WDB_FIND_GROUP,
    WDB_SELECT_GROUPS,
    WDB_DELETE_AGENT,
    WDB_DELETE_GROUP,
    WDB_DELETE_AGENT_BELONG,
    WDB_DELETE_GROUP_BELONG
} global_db_access;

typedef struct wdb_t {
    sqlite3 * db;
    sqlite3_stmt * stmt[WDB_STMT_SIZE];
    char * id;
    unsigned int refcount;
    unsigned int transaction:1;
    time_t last;
    time_t transaction_begin_time;
    pthread_mutex_t mutex;
    struct wdb_t * next;
} wdb_t;

typedef struct wdb_config {
    int sock_queue_size;
    int worker_pool_size;
    int commit_time_min;
    int commit_time_max;
    int open_db_limit;
} wdb_config;

/// Enumeration of components supported by the integrity library.
typedef enum {
    WDB_FIM         ///< File integrity monitoring.
} wdb_component_t;

extern char *schema_global_sql;
extern char *schema_agents_sql;
extern char *schema_upgrade_v1_sql;
extern char *schema_upgrade_v2_sql;
extern char *schema_upgrade_v3_sql;
extern char *schema_upgrade_v4_sql;
extern char *schema_upgrade_v5_sql;
extern char *schema_global_upgrade_v1_sql;

extern wdb_config wconfig;
extern pthread_mutex_t pool_mutex;
extern wdb_t * db_pool;
extern int db_pool_size;
extern OSHash * open_dbs;

typedef struct os_data {
    char *os_name;
    char *os_version;
    char *os_major;
    char *os_minor;
    char *os_codename;
    char *os_platform;
    char *os_build;
    char *os_uname;
    char *os_arch;
} os_data;

typedef struct agent_info_data {
    int id;
    os_data *osd;
    char *version;
    char *config_sum;
    char *merged_sum;
    char *manager_host;
    char *node_name;
    char *agent_ip;
    char *labels;
    char *sync_status;
} agent_info_data;

/**
 * @brief Opens global database and stores it in DB pool.
 *
 * It is opened every time a query to global database is done.
 *
 * @return wdb_t* Database Structure locked or NULL.
 */
wdb_t * wdb_open_global();

/**
 * @brief Open mitre database and store in DB poll.
 *
 * It is opened every time a query to Mitre database is done.
 *
 * @return wdb_t* Database Structure that store mitre database or NULL on failure.
 */
wdb_t * wdb_open_mitre();

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name);

// Open database for agent and store in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_agent2(int agent_id);

/* Get agent name from location string */
char* wdb_agent_loc2name(const char *location);

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_find_file(sqlite3 *db, const char *path, int type);

/* Find file, Returns ID, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type);

/* Get last event from file: returns WDB_FIM_*, or -1 on error. */
int wdb_get_last_fim(sqlite3 *db, const char *path, int type);

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(sqlite3 *db, int type, long timestamp, const char *f_name, const char *event, const sk_sum_t *sum);

int wdb_syscheck_load(wdb_t * wdb, const char * file, char * output, size_t size);

int wdb_syscheck_save(wdb_t * wdb, int ftype, char * checksum, const char * file);
int wdb_syscheck_save2(wdb_t * wdb, const char * payload);

// Find file entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_fim_find_entry(wdb_t * wdb, const char * path);

int wdb_fim_insert_entry(wdb_t * wdb, const char * file, int ftype, const sk_sum_t * sum);
int wdb_fim_insert_entry2(wdb_t * wdb, const cJSON * data);

int wdb_fim_update_entry(wdb_t * wdb, const char * file, const sk_sum_t * sum);

int wdb_fim_delete(wdb_t * wdb, const char * file);

/* Insert configuration assessment entry. Returns ID on success or -1 on error. */
int wdb_rootcheck_insert(wdb_t * wdb, const rk_event_t *event);

/* Update configuration assessment last date. Returns number of affected rows on success or -1 on error. */
int wdb_rootcheck_update(wdb_t * wdb, const rk_event_t *event);

/* Look for a configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_find(wdb_t * wdb, int pm_id, char * output);

/* Update a configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_update(wdb_t * wdb, char * result, int id,int scan_id, char * status, char * reason);

/* Insert configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_save(wdb_t *wdb, int id, int scan_id, char *title, char *description, char *rationale,
        char *remediation, char *condition, char *file, char *directory, char *process, char *registry,
        char *reference, char *result, char *policy_id, char *command, char *status, char *reason);

/* Insert scan info configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_scan_info_save(wdb_t * wdb, int start_scan, int end_scan, int scan_id,char * policy_id,int pass,int fail,int invalid, int total_checks,int score,char * hash);

/* Update scan info configuration assessment entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_scan_info_update(wdb_t * wdb, char * module, int end_scan);

/* Insert global configuration assessment compliance entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_compliance_save(wdb_t * wdb, int id_check, char *key, char *value);

/* Insert the rules of the policy checks,. Returns number of affected rows or -1 on error.  */
int wdb_sca_rules_save(wdb_t * wdb, int id_check, char *type, char *rule);

/* Look for a scan configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_scan_find(wdb_t * wdb, char *policy_id, char * output);

/* Update scan info configuration assessment entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_scan_info_update_start(wdb_t * wdb, char * policy_id, int start_scan,int end_scan,int scan_id,int pass,int fail,int invalid,int total_checks,int score,char * hash);

/* Look for a scan policy entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_policy_find(wdb_t * wdb, char *id, char * output);

/* Gets the result of all checks in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_checks_get_result(wdb_t * wdb, char * policy_id, char * output);

/* Insert policy entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_policy_info_save(wdb_t * wdb,char *name,char * file,char * id,char * description,char *references, char *hash_file);

/* Gets the result of all policies in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_policy_get_id(wdb_t * wdb, char * output);

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_policy_delete(wdb_t * wdb,char * policy_id);

/* Delete a configuration assessment check. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_delete(wdb_t * wdb,char * policy_id);

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_scan_info_delete(wdb_t * wdb,char * policy_id);

/* Delete a configuration assessment check compliances. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_compliances_delete(wdb_t * wdb);

/* Delete a configuration assessment check rules. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_rules_delete(wdb_t * wdb);

/* Delete distinct configuration assessment check. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_delete_distinct(wdb_t * wdb,char * policy_id,int scan_id);

/* Gets the policy SHA256. Returns 1 if found, 0 if not or -1 on error */
int wdb_sca_policy_sha256(wdb_t * wdb, char *id, char * output);

/**
 * @brief Frees agent_info_data struct memory.
 *
 * @param[in] agent_data Pointer to the struct to be freed.
 */
void wdb_free_agent_info_data(agent_info_data *agent_data);

/**
 * @brief Insert agent to the global.db.
 *
 * @param[in] id The agent ID.
 * @param[in] name The agent name.
 * @param[in] ip The agent ip address.
 * @param[in] register_ip The agent register IP.
 * @param[in] internal_key The client key of the agent.
 * @param[in] group The agent group.
 * @param[in] keep_date If 1, the addition date will be taken from agents-timestamp. If 0, the addition date is the current time.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_insert_agent(int id,
                     const char *name,
                     const char *ip,
                     const char *register_ip,
                     const char *internal_key,
                     const char *group,
                     int keep_date,
                     int *sock);

/**
 * @brief Insert a new group.
 *
 * @param[in] name The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_insert_group(const char *name, int *sock);

/**
 * @brief Update agent belongs table.
 *
 * @param[in] id_group Id of the group to be updated.
 * @param[in] id_agent Id of the agent to be updated.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_belongs(int id_group, int id_agent, int *sock);

/**
 * @brief Update agent name in global.db.
 *
 * @param[in] id The agent ID.
 * @param[in] name The agent name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_update_agent_name(int id, const char *name, int *sock);

/**
 * @brief Update agent data in global.db.
 *
 * @param[in] agent_data A pointer to an agent_info_data structure with the agent information.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_update_agent_data(agent_info_data *agent_data, int *sock);

/**
 * @brief Update agent's last keepalive ond modifies the cluster synchronization status.
 *
 * @param[in] id Id of the agent for whom the keepalive must be updated.
 * @param[in] sync_status String with the cluster synchronization status to be set.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_keepalive(int id, const char *sync_status, int *sock);

/**
 * @brief Set agent updating status.
 *
 * @param[in] id ID of the agent.
 * @param[in] status The status to be set. WDB_AGENT_EMPTY, WDB_AGENT_PENDING or WDB_AGENT_UPDATED.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS if success. OS_INVALID on error.
 */
int wdb_set_agent_status(int id_agent, int status, int *sock);

/**
 * @brief Update agent group. If the group is not specified, it is set to NULL.
 *
 * @param[in] id ID of the agent.
 * @param[in] group The group to be set.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS if success. OS_INVALID on error.
 */
int wdb_update_agent_group(int id,char *group, int *sock);

/**
 * @brief Update agent's labels.
 *
 * @param[in] id Id of the agent for whom the labels must be updated.
 * @param[in] labels String with the key-values separated by EOL.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_set_agent_labels(int id, const char *labels, int *sock);

/**
 * @brief Returns an array containing the ID of every agent (except 0), ended with -1.
 * This method creates and sends a command to WazuhDB to receive the ID of every agent.
 * If the response is bigger than the capacity of the socket, multiple commands will be sent until every agent ID is obtained.
 * The array is heap allocated memory that must be freed by the caller.
 *
 * @param [in] include_manager flag to include the manager on agents list
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Pointer to the array, on success.
 * @retval NULL on errors.
 */
int* wdb_get_all_agents(bool include_manager, int *sock);

/**
 * @brief Returns an array containing the ID of every agent (except 0), ended with -1 based on its keep_alive.
 * This method creates and sends a command to WazuhDB to receive the ID of every agent.
 * If the response is bigger than the capacity of the socket, multiple commands will be sent until every agent ID is obtained.
 * The array is heap allocated memory that must be freed by the caller.
 *
 * @param [in] condition The symbol ">" or "<". The condition to match keep alive.
 * @param [in] keepalive The keep_alive to search the agents.
 * @param [in] include_manager flag to include the manager on agents list.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Pointer to the array, on success. NULL on errors.
 */
int* wdb_get_agents_by_keepalive(const char* condition, int keepalive, bool include_manager, int *sock);

/**
 * @brief Find agent id by name and address.
 *
 * @param[in] name Name of the agent.
 * @param[in] ip IP address of the agent.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns id if success. OS_INVALID on error.
 */
int wdb_find_agent(const char *name, const char *ip, int *sock);

/**
 * @brief Returns a JSON with all the agent's information.
 *
 * @param[in] id Id of the agent for whom the information is requested.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return JSON* with the information on success or NULL on failure.
 */
cJSON* wdb_get_agent_info(int id, int *sock);

/**
 * @brief Returns a JSON with all the agent's labels.
 *
 * @param[in] id Id of the agent for whom the labels are requested.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return JSON* with the labels on success or NULL on failure.
 */
cJSON* wdb_get_agent_labels(int id, int *sock);

/**
 * @brief Get name from agent table in global.db by using its ID.
 *
 * @param[in] id Id of the agent that the name must be selected.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return A string with the agent name on success or NULL on failure.
 */
char* wdb_get_agent_name(int id, int *sock);

/**
 * @brief Get group from agent table in global.db by using its ID.
 *
 * @param[in] id Id of the agent that the name must be selected.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return A string with the agent group on success or NULL on failure.
 */
char* wdb_get_agent_group(int id, int *sock);

/**
 * @brief Get agent updating status.
 *
 * @param[in] id_agent ID of the agent.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns the WDB_AGENT_* status if success. OS_INVALID on error.
 */
int wdb_get_agent_status(int id_agent, int *sock);

/**
 * @brief Function to get the agent last keepalive.
 *
 * @param [in] name String with the name of the agent.
 * @param [in] ip String with the ip of the agent.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns this value, 0 on NULL or OS_INVALID on error.
 */
time_t wdb_get_agent_keepalive(const char *name, const char *ip, int *sock);

/**
 * @brief Find group by name.
 *
 * @param[in] name The group name.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns id if success or OS_INVALID on failure.
 */
int wdb_find_group(const char *name, int *sock);

/**
 * @brief Update groups table.
 *
 * @param[in] name The groups directory.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS if success or OS_INVALID on failure.
 */
int wdb_update_groups(const char *dirname, int *sock);

/**
 * @brief Delete an agent from agent table in global.db by using its ID.
 *
 * @param[in] id Id of the agent to be deleted.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_agent(int id, int *sock);

/**
 * @brief Delete group.
 *
 * @param[in] name The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_group_db(const char *name, int *sock);

/**
 * @brief Delete an agent from belongs table in global.db by using its ID.
 *
 * @param[in] id Id of the agent to be deleted.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_delete_agent_belongs(int id, int *sock);

/**
 * @brief Delete group from belongs table.
 *
 * @param[in] name The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_group_from_belongs_db(const char *name, int *sock);

/**
 * @brief Create database for agent from profile.
 *
 * @param[in] id Id of the agent.
 * @param[in] name Name of the agent.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_create_agent_db(int id, const char *name);

/**
 * @brief Create database for agent from profile.
 *
 * @param[in] agent_id Id of the agent.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_create_agent_db2(const char * agent_id);

/**
 * @brief Remove an agent's database.
 *
 * @param[in] id Id of the agent for whom its database must be deleted.
 * @param[in] name Name of the agent for whom its database must be deleted.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_agent_db(int id, const char * name);

/**
 * @brief Update agent multi group.
 *
 * @param[in] id The agent id.
 * @param[in] group The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_multi_group(int id, char *group, int *sock);

/**
 * @brief Fill belongs table on start.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 *
 * @return Returns OS_SUCCESS.
 */
int wdb_agent_belongs_first_time(int *sock);

/**
 * @brief Get the agent first registration date.
 *
 * @param[in] agent_id The agent ID.
 * @return Returns the agent first registration date.
 */
time_t get_agent_date_added(int agent_id);

/* Remove agents databases from id's list. */
cJSON *wdb_remove_multiple_agents(char *agent_list);

/* Insert or update metadata entries. Returns 0 on success or -1 on error. */
int wdb_fim_fill_metadata(wdb_t * wdb, char *data);

/* Find metadata entries. Returns 0 if doesn't found, 1 on success or -1 on error. */
int wdb_metadata_find_entry(wdb_t * wdb, const char * key);

/* Insert entry. Returns 0 on success or -1 on error. */
int wdb_metadata_insert_entry (wdb_t * wdb, const char *key, const char *value);

/* Update entries. Returns 0 on success or -1 on error. */
int wdb_metadata_update_entry (wdb_t * wdb, const char *key, const char *value);

/* Insert metadata for minor and major version. Returns 0 on success or -1 on error. */
int wdb_metadata_fill_version(sqlite3 *db);

/* Get value data in output variable. Returns 0 if doesn't found, 1 on success or -1 on error. */
int wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output);

/**
 * @brief Checks if the table exists in the database.
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[in] key Name of the table to find.
 * @return 1 if the table exists, 0 if the table doesn't exist or OS_INVALID on failure.
 */
 int wdb_metadata_table_check(wdb_t * wdb, const char * key);

/* Update field date for specific fim_entry. */
int wdb_fim_update_date_entry(wdb_t * wdb, const char *path);

/* Clear entries prior to the first scan. */
int wdb_fim_clean_old_entries(wdb_t * wdb);

/* Prepare SQL query with availability waiting */
int wdb_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail);

/* Execute statement with availability waiting */
int wdb_step(sqlite3_stmt *stmt);

/* Begin transaction */
int wdb_begin(sqlite3 *db);
int wdb_begin2(wdb_t * wdb);

/* Commit transaction */
int wdb_commit(sqlite3 *db);
int wdb_commit2(wdb_t * wdb);

/* Create global database */
int wdb_create_global(const char *path);

/* Create profile database */
int wdb_create_profile(const char *path);

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source);

/* Delete FIM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_fim(int id);

/* Delete FIM events of all agents. */
void wdb_delete_fim_all();

/* Delete PM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_pm(int id);

/* Delete PM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_rootcheck_delete(wdb_t * wdb);

/* Deletes PM events of all agents */
void wdb_delete_pm_all();

/* Rebuild database. Returns 0 on success or -1 on error. */
int wdb_vacuum(sqlite3 *db);

/* Insert key-value pair into info table */
int wdb_insert_info(const char *key, const char *value);

// Insert network info tuple. Return 0 on success or -1 on error.
int wdb_netinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped);

// Save Network info into DB.
int wdb_netinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped);

// Delete Network info from DB.
int wdb_netinfo_delete(wdb_t * wdb, const char * scan_id);

// Delete Hotfix info from DB.
int wdb_hotfix_delete(wdb_t * wdb, const char * scan_id);

// Set hotfix metadata.
int wdb_set_hotfix_metadata(wdb_t * wdb, const char * scan_id);

// Insert IPv4/IPv6 protocol info tuple. Return 0 on success or -1 on error.
int wdb_netproto_insert(wdb_t * wdb, const char * scan_id, const char * iface,  int type, const char * gateway, const char * dhcp, int metric);

// Save IPv4/IPv6 protocol info into DB.
int wdb_netproto_save(wdb_t * wdb, const char * scan_id, const char * iface,  int type, const char * gateway, const char * dhcp, int metric);

// Insert IPv4/IPv6 address info tuple. Return 0 on success or -1 on error.
int wdb_netaddr_insert(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast);

// Save IPv4/IPv6 address info into DB.
int wdb_netaddr_save(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast);

// Insert OS info tuple. Return 0 on success or -1 on error.
int wdb_osinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release);

// Save OS info into DB.
int wdb_osinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release);

// Insert HW info tuple. Return 0 on success or -1 on error.
int wdb_hardware_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, const char * cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage);

// Save HW info into DB.
int wdb_hardware_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, const char * cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage);

// Insert package info tuple. Return 0 on success or -1 on error.
int wdb_package_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location, const char triaged);

// Save Packages info into DB.
int wdb_package_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location);

// Insert hotfix info tuple. Return 0 on success or -1 on error.
int wdb_hotfix_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix);

// Save Hotfixes info into DB.
int wdb_hotfix_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix);

// Update the new Package info with the previous scan.
int wdb_package_update(wdb_t * wdb, const char * scan_id);

// Delete Packages info about previous scan from DB.
int wdb_package_delete(wdb_t * wdb, const char * scan_id);

// Insert process info tuple. Return 0 on success or -1 on error.
int wdb_process_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, int start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor);

// Save Process info into DB.
int wdb_process_save(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, int start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor);

// Delete Process info about previous scan from DB.
int wdb_process_delete(wdb_t * wdb, const char * scan_id);

// Insert port info tuple. Return 0 on success or -1 on error.
int wdb_port_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, const char * state, int pid, const char * process);

// Save port info into DB.
int wdb_port_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, const char * state, int pid, const char * process);

// Delete port info about previous scan from DB.
int wdb_port_delete(wdb_t * wdb, const char * scan_id);

// Save CIS-CAT scan results.
int wdb_ciscat_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, const char * profile, int pass, int fail, int error, int notchecked, int unknown, int score);

// Insert CIS-CAT results tuple. Return 0 on success or -1 on error.
int wdb_ciscat_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, const char * profile, int pass, int fail, int error, int notchecked, int unknown, int score);

// Delete old information from the 'ciscat_results' table
int wdb_ciscat_del(wdb_t * wdb, const char * scan_id);

wdb_t * wdb_init(sqlite3 * db, const char * id);

void wdb_destroy(wdb_t * wdb);

void wdb_pool_append(wdb_t * wdb);

void wdb_pool_remove(wdb_t * wdb);

void wdb_close_all();

void wdb_commit_old();

void wdb_close_old();

int wdb_remove_database(const char * agent_id);

/**
 * @brief Function to execute a SQL statement and save the result in a JSON array.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @return JSON array with the statement execution results. NULL On error.
 */
cJSON * wdb_exec_stmt(sqlite3_stmt * stmt);

/**
 * @brief Function to execute a SQL query and save the result in a JSON array.
 *
 * @param [in] db The SQL database to be queried.
 * @param [in] sql The SQL query.
 * @return JSON array with the query results. NULL On error.
 */
cJSON * wdb_exec(sqlite3 * db, const char * sql);

// Execute SQL script into an database
int wdb_sql_exec(wdb_t *wdb, const char *sql_exec);

int wdb_close(wdb_t * wdb, bool commit);

void wdb_leave(wdb_t * wdb);

wdb_t * wdb_pool_find_prev(wdb_t * wdb);

int wdb_stmt_cache(wdb_t * wdb, int index);

int wdb_parse(char * input, char * output);

int wdb_parse_syscheck(wdb_t * wdb, char * input, char * output);

/**
 * @brief Parses a rootcheck command
 * Commands:
 * 1. delete: Deletes pm table
 * 2. save: Inserts the entry or updates if it already exists
 * @param wdb Database of an agent
 * @param input buffer input
 * @param output buffer output, on success responses are:
 *        "ok 0" -> If entry was deleted
 *        "ok 1" -> If entry was updated
 *        "ok 2" -> If entry was inserted
 * */
int wdb_parse_rootcheck(wdb_t * wdb, char * input , char * output) __attribute__((nonnull));

int wdb_parse_netinfo(wdb_t * wdb, char * input, char * output);

int wdb_parse_netproto(wdb_t * wdb, char * input, char * output);

int wdb_parse_netaddr(wdb_t * wdb, char * input, char * output);

int wdb_parse_osinfo(wdb_t * wdb, char * input, char * output);

int wdb_parse_hardware(wdb_t * wdb, char * input, char * output);

int wdb_parse_packages(wdb_t * wdb, char * input, char * output);

int wdb_parse_hotfixes(wdb_t * wdb, char * input, char * output);

int wdb_parse_ports(wdb_t * wdb, char * input, char * output);

int wdb_parse_processes(wdb_t * wdb, char * input, char * output);

int wdb_parse_ciscat(wdb_t * wdb, char * input, char * output);

int wdb_parse_sca(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to get values from MITRE database.
 *
 * @param [in] wdb The MITRE struct database.
 * @param [in] input The query to get a value.
 * @param [out] output The response of the query.
 * @return 1 Success: response contains the value. 0 On error: the value was not found. -1 On error: invalid DB query syntax.
 */
int wdb_parse_mitre_get(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent insert request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_insert_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent name request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_update_agent_name(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent data request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_update_agent_data(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the labels request for a particular agent.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query in JSON format.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_agent_labels(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to get all the agent information in global.db.
 *
 * @param wdb The global struct database.
 * @param input String with 'agent_id'.
 * @param output Response of the query in JSON format.
 * @retval 0 Success: response contains the value.
 * @retval -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_agent_info(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse string with agent's labels and set them in labels table in global database.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id labels_string'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_set_agent_labels(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent keepalive request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_update_agent_keepalive(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent delete from agent table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_delete_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent name request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_select_agent_name(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_select_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent delete from belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_delete_agent_belong(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the find agent request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String JSON with the agent name and ip.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_find_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent update status request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK followed by a JSON with the status. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_select_agent_status(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent update status request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent and update status data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_update_agent_status(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent and group data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_update_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the find group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_find_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the insert group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_insert_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the insert agent to belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group id and agent id in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_insert_agent_belong(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the delete group from belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_delete_group_belong(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the delete group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_delete_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select groups request.
 *
 * @param [in] wdb The global struct database.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_select_groups(wdb_t * wdb, char * output);

/**
 * @brief Function to parse the select keepalive request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_name agent_ip'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value OK. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_select_agent_keepalive(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse sync-agent-info-get params and set next ID to iterate on further calls.
 *        If no last_id is provided. Last obtained ID is used.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with starting ID [optional].
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_sync_agent_info_get(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse agent_info and update the agents info from workers.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agents information in JSON format.
 * @param [out] output Response of the query in JSON format.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_sync_agent_info_set(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse last_id, condition and keepalive for get-agents-by-keepalive.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with last_id, condition, and keepalive.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_agents_by_keepalive(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse last_id get-all-agents.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with last_id, condition, and keepalive.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_all_agents(wdb_t* wdb, char* input, char* output);

int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest);

int wdbi_delete(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, const char * tail);

void wdbi_update_attempt(wdb_t * wdb, wdb_component_t component, long timestamp);

// Functions to manage scan_info table, this table contains the timestamp of every scan of syscheck ¿and syscollector?

int wdb_scan_info_update(wdb_t * wdb, const char *module, const char *field, long value);
int wdb_scan_info_get(wdb_t * wdb, const char *module, char *field, long *output);
int wdb_scan_info_fim_checks_control (wdb_t * wdb, const char *last_check);

// Upgrade agent database to last version
wdb_t * wdb_upgrade(wdb_t *wdb);

/**
 * @brief Function to upgrade Global DB to the latest version.
 *
 * @param [in] wdb The global.db database to upgrade.
 * @return wdb The global.db database updated on success.
 */
wdb_t * wdb_upgrade_global(wdb_t *wdb);

// Create backup and generate an empty DB
wdb_t * wdb_backup(wdb_t *wdb, int version);

/* Create backup for agent. Returns 0 on success or -1 on error. */
int wdb_create_backup(const char * agent_id, int version);

/**
 * @brief Function to backup Global DB in case of an upgrade failure.
 *
 * @param [in] wdb The global.db database to backup.
 * @param [in] version The global.db database version to backup.
 * @return wdb The new empty global.db database on success or NULL on error
 */
wdb_t * wdb_backup_global(wdb_t *wdb, int version);

/**
 * @brief Function to create the Global DB backup file.
 *
 * @param [in] wdb The global.db database to backup.
 * @param [in] version The global.db database version to backup.
 * @return wdb OS_SUCESS on success or OS_INVALID on error.
 */
int wdb_create_backup_global(int version);

/**
 * @brief Query the checksum of a data range
 *
 * Check that the accumulated checksum of every item between begin and
 * end (included) ordered alphabetically matches the checksum provided.
 *
 * On success, also delete every file between end and tail (if provided),
 * none of them included.
 *
 * @param [in] wdb Database node.
 * @param [in] component Name of the component.
 * @param [in] command Integrity check subcommand: "integrity_check_global", "integrity_check_left" or "integrity_check_right".
 * @param [in] payload Operation arguments in JSON format.
 * @pre payload must contain strings "id", "begin", "end" and "checksum", and optionally "tail".
 * @retval 2 Success: checksum matches.
 * @retval 1 Success: checksum does not match.
 * @retval 0 Success: no files were found in this range.
 * @retval -1 On error.
 */
int wdbi_query_checksum(wdb_t * wdb, wdb_component_t component, const char * command, const char * payload);

/**
 * @brief Query a complete table clear
 *
 * @param [in] wdb Database node.
 * @param [in] component Name of the component.
 * @param [in] payload Operation arguments in JSON format.
 * @pre payload must contain string "id".
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdbi_query_clear(wdb_t * wdb, wdb_component_t component, const char * payload);

/**
 * @brief Set the database journal mode to write-ahead logging
 *
 * @param [in] db Pointer to an open database.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdb_journal_wal(sqlite3 *db);

/**
 * @brief Function to get a MITRE technique's name.
 *
 * @param [in] wdb The MITRE struct database.
 * @param [in] id MITRE technique's ID.
 * @param [out] output MITRE technique's name.
 * @retval 1 Sucess: name found on MITRE database.
 * @retval 0 On error: name not found on MITRE database.
 * @retval -1 On error: invalid DB query syntax.
 */
int wdb_mitre_name_get(wdb_t *wdb, char *id, char *output);

/**
 * @brief Function to insert an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] name The agent name
 * @param [in] ip The agent IP address
 * @param [in] register_ip The agent registration IP address
 * @param [in] internal_key The agent key
 * @param [in] group The agent group
 * @param [in] date_add The agent addition date.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key, char* group, int date_add);

/**
 * @brief Function to update an agent name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] name The agent name
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_name(wdb_t *wdb, int id, char* name);

/**
 * @brief Function to update an agent version data.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID.
 * @param [in] os_name The agent's operating system name.
 * @param [in] os_version The agent's operating system version.
 * @param [in] os_major The agent's operating system major version.
 * @param [in] os_minor The agent's operating system minor version.
 * @param [in] os_codename The agent's operating system code name.
 * @param [in] os_platform The agent's operating system platform.
 * @param [in] os_build The agent's operating system build number.
 * @param [in] os_uname The agent's operating system uname.
 * @param [in] os_arch The agent's operating system architecture.
 * @param [in] version The agent's version.
 * @param [in] config_sum The agent's configuration sum.
 * @param [in] merged_sum The agent's merged sum.
 * @param [in] manager_host The agent's manager host name.
 * @param [in] node_name The agent's manager node name.
 * @param [in] agent_ip The agent's IP address.
 * @param [in] sync_status The agent's synchronization status in cluster.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_version(wdb_t *wdb,
                                    int id,
                                    const char *os_name,
                                    const char *os_version,
                                    const char *os_major,
                                    const char *os_minor,
                                    const char *os_codename,
                                    const char *os_platform,
                                    const char *os_build,
                                    const char *os_uname,
                                    const char *os_arch,
                                    const char *version,
                                    const char *config_sum,
                                    const char *merged_sum,
                                    const char *manager_host,
                                    const char *node_name,
                                    const char *agent_ip,
                                    const char *sync_status);

/**
 * @brief Function to get the labels of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with labels on success. NULL on error.
 */
cJSON* wdb_global_get_agent_labels(wdb_t *wdb, int id);

/**
 * @brief Function to delete the labels of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return 0 On success. -1 On error.
 */
int wdb_global_del_agent_labels(wdb_t *wdb, int id);

/**
 * @brief Function to insert a label of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] key A string with the label key.
 * @param [in] value A string with the label value.
 * @return 0 On success. -1 On error.
 */
int wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value);

/**
 * @brief Function to update an agent keepalive and the synchronization status.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] status The value of sync_status
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_keepalive(wdb_t *wdb, int id, const char *sync_status);

/**
 * @brief Function to delete an agent from the agent table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_agent(wdb_t *wdb, int id);

/**
 * @brief Function to get the name of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with the agent name on success. NULL on error.
 */
cJSON* wdb_global_select_agent_name(wdb_t *wdb, int id);

/**
 * @brief Function to get the group of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with the agent group on success. NULL on error.
 */
cJSON* wdb_global_select_agent_group(wdb_t *wdb, int id);

/**
 * @brief Function to delete an agent from the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_agent_belong(wdb_t *wdb, int id);

/**
 * @brief Function to get an agent id using the agent name and register ip.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] name The agent name
 * @param [in] ip The agent ip
 * @return JSON with id on success. NULL on error.
 */
cJSON* wdb_global_find_agent(wdb_t *wdb, const char *name, const char *ip);

/**
 * @brief Function to get the update status of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with the agent update status on success. NULL on error.
 */
cJSON* wdb_global_select_agent_status(wdb_t *wdb, int id);

/**
 * @brief Function to update an agent update status.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] status The value of the status
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_status(wdb_t *wdb, int id, char *status);

/**
 * @brief Function to update an agent group.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] group The group to be set
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_group(wdb_t *wdb, int id, char *group);

/**
 * @brief Function to get a group id using the group name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return JSON with group id on success. NULL on error.
 */
cJSON* wdb_global_find_group(wdb_t *wdb, char* group_name);

/**
 * @brief Function to insert a group using the group name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent_group(wdb_t *wdb, char* group_name);

/**
 * @brief Function to insert an agent to the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id_group The group id.
 * @param [in] id_agent The agent id.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent);

/**
 * @brief Function to delete a group from belongs table using the group name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_group_belong(wdb_t *wdb, char* group_name);

/**
 * @brief Function to delete a group by using the name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_group(wdb_t *wdb, char* group_name);

/**
 * @brief Function to get a list of groups.
 *
 * @param [in] wdb The Global struct database.
 * @return JSON with all the groups on success. NULL on error.
 */
cJSON* wdb_global_select_groups(wdb_t *wdb);

/**
 * @brief Function to get an agent keepalive using the agent name and register ip.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] name The agent name
 * @param [in] ip The agent ip
 * @return JSON with last_keepalive on success. NULL on error.
 */
cJSON* wdb_global_select_agent_keepalive(wdb_t *wdb, char* name, char* ip);

/**
 * @brief Function to update sync_status of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] status The value of sync_status
 * @return 0 On success. -1 On error.
 */
int wdb_global_set_sync_status(wdb_t *wdb, int id, const char *sync_status);

/**
 * @brief Gets and parses agents with 'syncreq' sync_status and sets them to 'synced'.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [out] output A buffer where the response is written. Must be de-allocated by the caller.
 * @return wdbc_result to represent if all agents has being obtained.
 */
wdbc_result wdb_global_sync_agent_info_get(wdb_t *wdb, int* last_agent_id, char **output);

/**
 * @brief Function to update the information of an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] agent_info A JSON array with the agent information.
 * @return 0 On success. -1 On error.
 */
int wdb_global_sync_agent_info_set(wdb_t *wdb, cJSON *agent_info);

/**
 * @brief Function to get the information of a particular agent stored in Wazuh DB.
 *
 * @param wdb The Global struct database.
 * @param id Agent id.
 * @retval JSON with agent information on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agent_info(wdb_t *wdb, int id);

/*
 * @brief Gets every agent ID based on the keepalive.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [in] condition The symbol '<' or '>' condition used to compare keepalive.
 * @param [in] keep_alive The value of keepalive to search for agents.
 * @param [out] output A buffer where the response is written. Must be de-allocated by the caller.
 * @return wdbc_result to represent if all agents has being obtained or any error occurred.
 */
wdbc_result wdb_global_get_agents_by_keepalive(wdb_t *wdb, int* last_agent_id, char condition, int keep_alive, char **output);

/**
 * @brief Gets every agent ID.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [out] output A buffer where the response is written. Must be de-allocated by the caller.
 * @return wdbc_result to represent if all agents has being obtained or any error occurred.
 */
wdbc_result wdb_global_get_all_agents(wdb_t *wdb, int* last_agent_id, char **output);

// Finalize a statement securely
#define wdb_finalize(x) { if (x) { sqlite3_finalize(x); x = NULL; } }

/**
 * @brief Check the agent 0 status in the global database
 *
 * The table "agent" must have a tuple with id=0 and last_keepalive=1999/12/31 23:59:59 UTC.
 * Otherwise, the database is either corrupt or old.
 *
 * @return Number of tuples matching that condition.
 * @retval 1 The agent 0 status is OK.
 * @retval 0 No tuple matching conditions exists.
 * @retval -1 The table "agent" is missing or an error occurred.
 */
int wdb_global_check_manager_keepalive(wdb_t *wdb);

#endif

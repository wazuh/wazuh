/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
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
#include "../external/sqlite/sqlite3.h"
#include "syscheck_op.h"
#include "rootcheck_op.h"
#include "wazuhdb_op.h"
#include "regex_op.h"
#include "router.h"
#include "../config/global-config.h"

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

#define WDB_NETADDR_IPV4 0

#define WDB_MULTI_GROUP_DELIM '-'

#define WDB_RESPONSE_BEGIN_SIZE 16

#define WDB_DATABASE_LOGTAG ARGV0 ":wdb_agent"

#define WDB_MAX_COMMAND_SIZE    512
#define WDB_MAX_RESPONSE_SIZE   OS_MAXSTR-WDB_MAX_COMMAND_SIZE
#define WDB_MAX_QUERY_SIZE      OS_MAXSTR-WDB_MAX_COMMAND_SIZE

#define AGENT_CS_NEVER_CONNECTED "never_connected"
#define AGENT_CS_PENDING         "pending"
#define AGENT_CS_ACTIVE          "active"
#define AGENT_CS_DISCONNECTED    "disconnected"

/// Enumeration of agents disconected status reasons.
typedef enum agent_status_code_t {
        INVALID_VERSION = 1,    ///< Invalid agent version
        ERR_VERSION_RECV,       ///< Error retrieving version
        HC_SHUTDOWN_RECV,       ///< Shutdown message received
        NO_KEEPALIVE,           ///< Disconnected because no keepalive received
        RESET_BY_MANAGER,       ///< Connection reset by manager
} agent_status_code_t;

/* wdb_exec_row_stmt modes */
#define STMT_MULTI_COLUMN 0
#define STMT_SINGLE_COLUMN 1

/// Enumeration of agent groups sync conditions
typedef enum wdb_groups_sync_condition_t {
        WDB_GROUP_SYNC_STATUS,      ///< Get groups by their sync status
        WDB_GROUP_ALL,              ///< Get all groups
        WDB_GROUP_NO_CONDITION,     ///< No condition
        WDB_GROUP_INVALID_CONDITION ///< Invalid condition
} wdb_groups_sync_condition_t;

/// Enumeration of agent groups set mode
typedef enum wdb_groups_set_mode_t {
        WDB_GROUP_OVERRIDE,     ///< Re-write the group assignment
        WDB_GROUP_APPEND,       ///< Add group assignment to the existent one
        WDB_GROUP_EMPTY_ONLY,   ///< Write a group assignment only if the agent doesn´t have one
        WDB_GROUP_REMOVE,       ///< Removes a list of group assignments
        WDB_GROUP_INVALID_MODE  ///< Invalid mode
} wdb_groups_set_mode_t;

/// Operations with the global group hash cache
typedef enum wdb_global_group_hash_operations_t {
    WDB_GLOBAL_GROUP_HASH_READ,  ///< Reads the global group hash value in cache if any
    WDB_GLOBAL_GROUP_HASH_WRITE, ///< Saves a new global group hash value in cache
    WDB_GLOBAL_GROUP_HASH_CLEAR  ///< Erases the global group hash value in cache
} wdb_global_group_hash_operations_t;

#define WDB_GROUP_MODE_EMPTY_ONLY "empty_only"
#define WDB_GROUP_MODE_OVERRIDE "override"
#define WDB_GROUP_MODE_APPEND "append"

#define WDB_GROUP_HASH_SIZE        8 /* Size of the groups hash */

#define WDB_BLOCK_SEND_TIMEOUT_S   1 /* Max time in seconds waiting for the client to receive the information sent with a blocking method*/
#define WDB_RESPONSE_OK_SIZE     3

#define SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE "legacy"

// Router provider variables
extern ROUTER_PROVIDER_HANDLE router_agent_events_handle;
extern ROUTER_PROVIDER_HANDLE router_fim_events_handle;
extern ROUTER_PROVIDER_HANDLE router_inventory_events_handle;

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
    WDB_STMT_OSINFO_INSERT2,
    WDB_STMT_OSINFO_DEL,
    WDB_STMT_OSINFO_GET,
    WDB_STMT_PROGRAM_INSERT,
    WDB_STMT_PROGRAM_INSERT2,
    WDB_STMT_PROGRAM_DEL,
    WDB_STMT_PROGRAM_UPD,
    WDB_STMT_PROGRAM_GET,
    WDB_STMT_PROGRAM_FIND,
    WDB_STMT_HWINFO_INSERT,
    WDB_STMT_HWINFO_INSERT2,
    WDB_STMT_HOTFIX_INSERT,
    WDB_STMT_HOTFIX_INSERT2,
    WDB_STMT_HWINFO_DEL,
    WDB_STMT_HOTFIX_DEL,
    WDB_STMT_PORT_INSERT,
    WDB_STMT_PORT_INSERT2,
    WDB_STMT_PORT_DEL,
    WDB_STMT_PROC_INSERT,
    WDB_STMT_PROC_INSERT2,
    WDB_STMT_PROC_DEL,
    WDB_STMT_NETINFO_INSERT,
    WDB_STMT_NETINFO_INSERT2,
    WDB_STMT_PROTO_INSERT,
    WDB_STMT_PROTO_INSERT2,
    WDB_STMT_ADDR_INSERT,
    WDB_STMT_ADDR_INSERT2,
    WDB_STMT_NETINFO_DEL,
    WDB_STMT_PROTO_DEL,
    WDB_STMT_ADDR_DEL,
    WDB_STMT_USER_INSERT,
    WDB_STMT_USER_INSERT2,
    WDB_STMT_GROUP_INSERT,
    WDB_STMT_GROUP_INSERT2,
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
    WDB_STMT_SCA_CHECK_DELETE_DISTINCT,
    WDB_STMT_FIM_SELECT_CHECKSUM,
    WDB_STMT_FIM_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_DELETE_AROUND,
    WDB_STMT_FIM_DELETE_RANGE,
    WDB_STMT_FIM_DELETE_BY_PK,
    WDB_STMT_FIM_CLEAR,
    WDB_STMT_SYNC_UPDATE_ATTEMPT_LEGACY,
    WDB_STMT_SYNC_UPDATE_ATTEMPT,
    WDB_STMT_SYNC_UPDATE_COMPLETION,
    WDB_STMT_SYNC_SET_COMPLETION,
    WDB_STMT_SYNC_GET_INFO,
    WDB_STMT_FIM_FILE_SELECT_CHECKSUM,
    WDB_STMT_FIM_FILE_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_FILE_CLEAR,
    WDB_STMT_FIM_FILE_DELETE_AROUND,
    WDB_STMT_FIM_FILE_DELETE_RANGE,
    WDB_STMT_FIM_FILE_DELETE_BY_PK,
    WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM,
    WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_CLEAR,
    WDB_STMT_FIM_REGISTRY_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM,
    WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_KEY_CLEAR,
    WDB_STMT_FIM_REGISTRY_KEY_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_KEY_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM,
    WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_VALUE_CLEAR,
    WDB_STMT_FIM_REGISTRY_VALUE_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_VALUE_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_DELETE_BY_PK,
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
    WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE,
    WDB_STMT_GLOBAL_DELETE_AGENT,
    WDB_STMT_GLOBAL_SELECT_AGENT_NAME,
    WDB_STMT_GLOBAL_FIND_AGENT,
    WDB_STMT_GLOBAL_FIND_GROUP,
    WDB_STMT_GLOBAL_UPDATE_AGENT_GROUPS_HASH,
    WDB_STMT_GLOBAL_INSERT_AGENT_GROUP,
    WDB_STMT_GLOBAL_SELECT_GROUP_BELONG,
    WDB_STMT_GLOBAL_INSERT_AGENT_BELONG,
    WDB_STMT_GLOBAL_DELETE_AGENT_BELONG,
    WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG,
    WDB_STMT_GLOBAL_DELETE_GROUP,
    WDB_STMT_GLOBAL_GROUP_BELONG_FIND,
    WDB_STMT_GLOBAL_GROUP_BELONG_GET,
    WDB_STMT_GLOBAL_SELECT_GROUPS,
    WDB_STMT_GLOBAL_SYNC_REQ_FULL_GET,
    WDB_STMT_GLOBAL_SYNC_REQ_STATUS_GET,
    WDB_STMT_GLOBAL_SYNC_REQ_KEEPALIVE_GET,
    WDB_STMT_GLOBAL_SYNC_GET,
    WDB_STMT_GLOBAL_SYNC_SET,
    WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET,
    WDB_STMT_GLOBAL_GROUP_SYNC_ALL_GET,
    WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND,
    WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET,
    WDB_STMT_GLOBAL_GROUP_SYNC_SET,
    WDB_STMT_GLOBAL_GROUP_PRIORITY_GET,
    WDB_STMT_GLOBAL_GROUP_CSV_GET,
    WDB_STMT_GLOBAL_GROUP_CTX_SET,
    WDB_STMT_GLOBAL_GROUP_HASH_GET,
    WDB_STMT_GLOBAL_GROUP_HASH_SET,
    WDB_STMT_GLOBAL_UPDATE_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_GROUPS,
    WDB_STMT_GLOBAL_GET_AGENTS,
    WDB_STMT_GLOBAL_GET_AGENTS_AND_GROUP,
    WDB_STMT_GLOBAL_GET_AGENTS_CONTEXT,
    WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE,
    WDB_STMT_GLOBAL_GET_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT,
    WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_AGENT_EXISTS,
    WDB_STMT_TASK_INSERT_TASK,
    WDB_STMT_TASK_GET_LAST_AGENT_TASK,
    WDB_STMT_TASK_GET_LAST_AGENT_UPGRADE_TASK,
    WDB_STMT_TASK_UPDATE_TASK_STATUS,
    WDB_STMT_TASK_GET_TASK_BY_STATUS,
    WDB_STMT_TASK_DELETE_OLD_TASKS,
    WDB_STMT_TASK_DELETE_TASK,
    WDB_STMT_TASK_CANCEL_PENDING_UPGRADE_TASKS,
    WDB_STMT_PRAGMA_JOURNAL_WAL,
    WDB_STMT_PRAGMA_ENABLE_FOREIGN_KEYS,
    WDB_STMT_PRAGMA_SYNCHRONOUS_NORMAL,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_PORTS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_NETINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_HWINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_OSINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_USERS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_USERS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_USERS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_USERS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_USERS_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_USERS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_GROUPS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_GROUPS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_GROUPS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_GROUPS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_GROUPS_DELETE_BY_PK,
    WDB_STMT_SYSCOLLECTOR_GROUPS_CLEAR,
    WDB_STMT_SYS_HOTFIXES_GET,
    WDB_STMT_SYS_PROGRAMS_GET,
    WDB_STMT_SIZE // This must be the last constant
} wdb_stmt;

struct stmt_cache {
    sqlite3_stmt *stmt;
    char *query;
};

struct stmt_cache_list {
    struct stmt_cache value;
    struct stmt_cache_list *next;
};

typedef struct wdb_t {
    sqlite3 * db;
    sqlite3_stmt * stmt[WDB_STMT_SIZE];
    char * id;
    int peer;
    _Atomic(unsigned int) refcount;
    unsigned int transaction:1;
    _Atomic(time_t) last;
    time_t transaction_begin_time;
    pthread_mutex_t mutex;
    struct stmt_cache_list *cache_list;
    struct wdb_t * next;
    bool enabled;
} wdb_t;

typedef enum wdb_backup_db {
    WDB_GLOBAL_BACKUP,
    WDB_LAST_BACKUP
} wdb_backup_db ;

typedef struct wdb_backup_settings_node {
    bool enabled;
    time_t interval;
    int max_files;
} wdb_backup_settings_node;

typedef struct wdb_config {
    int worker_pool_size;
    int commit_time_min;
    int commit_time_max;
    int open_db_limit;
    int fragmentation_threshold;
    int fragmentation_delta;
    int free_pages_percentage;
    int max_fragmentation;
    int check_fragmentation_interval;
    wdb_backup_settings_node** wdb_backup_settings;
} wdb_config;

/// Enumeration of components supported by the integrity library.
typedef enum {
    WDB_FIM,                         ///< File integrity monitoring.
    WDB_FIM_FILE,                    ///< File integrity monitoring.
    WDB_FIM_REGISTRY,                ///< Registry integrity monitoring.
    WDB_FIM_REGISTRY_KEY,            ///< Registry key integrity monitoring.
    WDB_FIM_REGISTRY_VALUE,          ///< Registry value integrity monitoring.
    WDB_SYSCOLLECTOR_PROCESSES,      ///< Processes integrity monitoring.
    WDB_SYSCOLLECTOR_PACKAGES,       ///< Packages integrity monitoring.
    WDB_SYSCOLLECTOR_HOTFIXES,       ///< Hotfixes integrity monitoring.
    WDB_SYSCOLLECTOR_PORTS,          ///< Ports integrity monitoring.
    WDB_SYSCOLLECTOR_NETPROTO,       ///< Net protocols integrity monitoring.
    WDB_SYSCOLLECTOR_NETADDRESS,     ///< Net addresses integrity monitoring.
    WDB_SYSCOLLECTOR_NETINFO,        ///< Net info integrity monitoring.
    WDB_SYSCOLLECTOR_HWINFO,         ///< Hardware info integrity monitoring.
    WDB_SYSCOLLECTOR_OSINFO,         ///< OS info integrity monitoring.
    WDB_SYSCOLLECTOR_USERS,          ///< Users info integrity monitoring.
    WDB_SYSCOLLECTOR_GROUPS,         ///< Groups info integrity monitoring.
    WDB_GENERIC_COMPONENT,           ///< Miscellaneous component
} wdb_component_t;

#include "wdb_pool.h"

extern char *schema_global_sql;
extern char *schema_agents_sql;
extern char *schema_task_manager_sql;
extern char *schema_upgrade_v1_sql;
extern char *schema_upgrade_v2_sql;
extern char *schema_upgrade_v3_sql;
extern char *schema_upgrade_v4_sql;
extern char *schema_upgrade_v5_sql;
extern char *schema_upgrade_v6_sql;
extern char *schema_upgrade_v7_sql;
extern char *schema_upgrade_v8_sql;
extern char *schema_upgrade_v9_sql;
extern char *schema_upgrade_v10_sql;
extern char *schema_upgrade_v11_sql;
extern char *schema_upgrade_v12_sql;
extern char *schema_upgrade_v13_sql;
extern char *schema_upgrade_v14_sql;
extern char *schema_upgrade_v15_sql;
extern char *schema_upgrade_v16_sql;
extern char *schema_global_upgrade_v1_sql;
extern char *schema_global_upgrade_v2_sql;
extern char *schema_global_upgrade_v3_sql;
extern char *schema_global_upgrade_v4_sql;
extern char *schema_global_upgrade_v5_sql;
extern char *schema_global_upgrade_v6_sql;
extern char *schema_global_upgrade_v7_sql;

extern wdb_config wconfig;
extern _Config gconfig;

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
    char *connection_status;
    char *sync_status;
    char *group_config_status;
    agent_status_code_t status_code;
} agent_info_data;

typedef enum {
    FIELD_INTEGER = 0,
    FIELD_TEXT,
    FIELD_REAL,
    FIELD_INTEGER_LONG
} field_type_t;

struct field {
    field_type_t type;
    int index;
    bool is_aux_field;
    bool is_pk;
    const char * source_name;
    const char * target_name;
    union {
        const char * text;
        int integer;
        double real;
        long long integer_long;
    } default_value;
    bool convert_empty_string_as_null;
};

struct column_list {
    struct field value;
    const struct column_list *next;
};

struct kv {
    char key[OS_SIZE_256];
    char value[OS_SIZE_256];
    bool single_row_table;
    struct column_list const *column_list;
    size_t field_count;
};

struct kv_list {
    struct kv current;
    const struct kv_list *next;
};


/**
 * @brief pointer to function for any transaction
 */
typedef int (*wdb_ptr_any_txn_t)(wdb_t *);

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

// Open database for agent and store in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_agent2(int agent_id);

/**
 * @brief Open task database and store in DB poll.
 *
 * It is opened every time a query to Task database is done.
 *
 * @return wdb_t* Database Structure that store task database or NULL on failure.
 */
wdb_t * wdb_open_tasks();

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
int wdb_sca_update(wdb_t * wdb, char * result, int id,int scan_id, char * reason);

/* Insert configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_save(wdb_t *wdb, int id, int scan_id, char *title, char *description, char *rationale,
        char *remediation, char *condition, char *file, char *directory, char *process, char *registry,
        char *reference, char *result, char *policy_id, char *command, char *reason);

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
 * @brief Function to parse a chunk response that contains the status of the query and a json array.
 *        This function will create or realloc an int array to place the values of the chunk.
 *        These values are obtained based on the provided json item string.
 *
 * @param [in] input The chunk obtained from WazuhDB to be parsed.
 * @param [out] output An int array containing the parsed values. Must be freed by the caller.
 * @param [in] item Json string to search elements on the chunks.
 * @param [out] last_item Value of the last parsed item. If NULL no value is written.
 * @param [out] last_size Size of the returned array. If NULL no value is written.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_parse_chunk_to_int(char* input, int** output, const char* item, int* last_item, int* last_size);

/**
 * @brief Function to parse a chunk response that contains the status of the query and a json array.
 *        This function will add the parsed response to the output_json (json) array.
 *
 * @param [in] input The chunk obtained from WazuhDB to be parsed.
 * @param [out] output_json Json array in which the new elements will be added.
 * @param [in] item Json string to search elements on the chunks.
 * @param [out] last_item_value Value of the last item. If NULL no value is written.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_parse_chunk_to_json_by_string_item(char* input, cJSON** output_json, const char* item, char** last_item_value);

/**
 * @brief Function to parse a chunk response that contains the status of the query and a json array.
 *        This function will add the parsed response to the output RB tree.
 *
 * @param [in] input The chunk obtained from WazuhDB to be parsed.
 * @param [out] output RB tree in which the new elements will be added.
 * @param [in] item Json string to search elements on the chunks.
 * @param [out] last_item Value of the last parsed item. If NULL no value is written.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_parse_chunk_to_rbtree(char* input, rb_tree** output, const char* item, int* last_item);

/**
 * @brief Function to initialize a new transaction and cache the statement.
 *
 * @param [in] wdb The global struct database.
 * @param [in] statement_index The index of the statement to be cached.
 * @return Pointer to the statement already cached. NULL On error.
 */
sqlite3_stmt* wdb_init_stmt_in_cache(wdb_t* wdb, wdb_stmt statement_index);

/**
 * @brief Create database for agent from profile.
 *
 * @param[in] agent_id Id of the agent.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_create_agent_db2(const char * agent_id);

/* Remove agents databases from id's list. */
cJSON *wdb_remove_multiple_agents(char *agent_list);

/* Get value data in output variable. Returns 0 if doesn't found, 1 on success or -1 on error. */
int wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output);

/**
 * @brief Gets the count of the tables that match the provided name
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[in] key Name of the table to find.
 * @param[in] returns the count
 * @return function success.
 */
 int wdb_count_tables_with_name(wdb_t * wdb, const char * key, int* count);

/* Update field date for specific fim_entry. */
int wdb_fim_update_date_entry(wdb_t * wdb, const char *path);

/* Clear entries prior to the first scan. */
int wdb_fim_clean_old_entries(wdb_t * wdb);

/* Prepare SQL query with availability waiting */
int wdb_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail);

/* Execute statement with availability waiting */
int wdb_step(sqlite3_stmt *stmt);

/* Begin transaction */
int wdb_begin(wdb_t * wdb);
int wdb_begin2(wdb_t * wdb);

/* Commit transaction */
int wdb_commit(wdb_t * wdb);
int wdb_commit2(wdb_t * wdb);

/**
 * @brief Rollback transaction
 * @param[in] wdb Database to query for the table existence.
 * @return 0 when succeed, !=0 otherwise.
*/
int wdb_rollback(wdb_t * wdb);

/**
 * @brief Rollback transaction and write status
 * @param[in] wdb Database to query for the table existence.
 * @return 0 when succeed, !=0 otherwise.
*/
int wdb_rollback2(wdb_t * wdb);

/* Create global database */
int wdb_create_global(const char *path);

/* Create profile database */
int wdb_create_profile();

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source);

/* Delete PM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_rootcheck_delete(wdb_t * wdb);

/**
 * @brief Rebuild database.
 * @param[in] wdb Database to query for the table existence.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_vacuum(wdb_t * wdb);

/**
 * @brief Calculate the fragmentation state of a db.
 *
 * @param[in] wdb Database to query for the table existence.
 * @return Returns 0-100 on success or OS_INVALID on error.
 */
int wdb_get_db_state(wdb_t * wdb);

/**
 * @brief Calculate the percentage of free pages of a db.
 *
 * @param[in] wdb Database to query for the table existence.
 * @return Returns zero or greater than zero on success or OS_INVALID on error.
 */
int wdb_get_db_free_pages_percentage(wdb_t * wdb);

/**
 * @brief Store the fragmentation data of the last vacuum in the metadata table.
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[in] last_vacuum_time Timestamp to store in the metadata table.
 * @param[in] last_vacuum_value Value to store in the metadata table.
 * @return Returns OS_SUCCES on success or OS_INVALID on error.
 */
int wdb_update_last_vacuum_data(wdb_t* wdb, const char *last_vacuum_time, const char *last_vacuum_value);

/* Insert key-value pair into info table */
int wdb_insert_info(const char *key, const char *value);

// Insert network info tuple. Return 0 on success or -1 on error.
int wdb_netinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped, const char * checksum, const char * item_id, const bool replace);

// Save Network info into DB.
int wdb_netinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped, const char * checksum, const char * item_id, const bool replace);

// Delete Network info from DB.
int wdb_netinfo_delete(wdb_t * wdb, const char * scan_id);

// Delete Hotfix info from DB.
int wdb_hotfix_delete(wdb_t * wdb, const char * scan_id);

// Insert IPv4/IPv6 protocol info tuple. Return 0 on success or -1 on error.
int wdb_netproto_insert(wdb_t * wdb, const char * scan_id, const char * iface,  int type, const char * gateway, const char * dhcp, int metric, const char * checksum, const char * item_id, const bool replace);

// Save IPv4/IPv6 protocol info into DB.
int wdb_netproto_save(wdb_t * wdb, const char * scan_id, const char * iface,  int type, const char * gateway, const char * dhcp, int metric, const char * checksum, const char * item_id, const bool replace);

// Insert IPv4/IPv6 address info tuple. Return 0 on success or -1 on error.
int wdb_netaddr_insert(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast, const char * checksum, const char * item_id, const bool replace);

// Save IPv4/IPv6 address info into DB.
int wdb_netaddr_save(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast, const char * checksum, const char * item_id, const bool replace);

// Insert OS info tuple. Return 0 on success or -1 on error.
int wdb_osinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_patch, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release, const char * os_display_version, const char * checksum, const bool replace, os_sha1 hexdigest);

// Save OS info into DB.
int wdb_osinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_patch, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release, const char * os_display_version, const char * checksum, const bool replace);

// Insert HW info tuple. Return 0 on success or -1 on error.
int wdb_hardware_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, double cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage, const char * checksum, const bool replace);

// Save HW info into DB.
int wdb_hardware_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, double cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage, const char * checksum, const bool replace);

// Insert package info tuple. Return 0 on success or -1 on error.
int wdb_package_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location, const char * checksum, const char * item_id, const bool replace);

// Save Packages info into DB.
int wdb_package_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location, const char* checksum, const char * item_id, const bool replace);

// Insert hotfix info tuple. Return 0 on success or -1 on error.
int wdb_hotfix_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix, const char * checksum, const bool replace);

// Save Hotfixes info into DB.
int wdb_hotfix_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix, const char * checksum, const bool replace);

// Update the new Package info with the previous scan.
int wdb_package_update(wdb_t * wdb, const char * scan_id);

// Delete Packages info about previous scan from DB.
int wdb_package_delete(wdb_t * wdb, const char * scan_id);

// Insert process info tuple. Return 0 on success or -1 on error.
int wdb_process_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, long long start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor, const char * checksum, const bool replace);

// Save Process info into DB.
int wdb_process_save(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, long long start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor, const char* checksum, const bool replace);

// Delete Process info about previous scan from DB.
int wdb_process_delete(wdb_t * wdb, const char * scan_id);

// Insert port info tuple. Return 0 on success or -1 on error.
int wdb_port_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, long long inode, const char * state, int pid, const char * process, const char * checksum, const char * item_id, const bool replace);

// Save port info into DB.
int wdb_port_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, long long inode, const char * state, int pid, const char * process, const char * checksum, const char * item_id, const bool replace);

// Delete port info about previous scan from DB.
int wdb_port_delete(wdb_t * wdb, const char * scan_id);

// Save user info into DB.
int wdb_users_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * user_name, const char * user_full_name, 
                   const char * user_home, int user_id, int user_uid_signed, const char * user_uuid, const char * user_groups, 
                   int user_group_id, int user_group_id_signed, double user_created, const char * user_roles, const char * user_shell, 
                   const char * user_type, const bool user_is_hidden, const bool user_is_remote, long user_last_login, 
                   int user_auth_failed_count, double user_auth_failed_timestamp, double user_password_last_set_time, 
                   int user_password_expiration_date, const char * user_password_hash_algorithm, int user_password_inactive_days,
                   int user_password_last_change, int user_password_max_days_between_changes, int user_password_min_days_between_changes,
                   const char * user_password_status, int user_password_warning_days_before_expiration, long process_pid, const char * host_ip,
                   const bool login_status, const char * login_type, const char * login_tty, const char * checksum, const bool replace);

// Insert user info tuple. Return 0 on success or -1 on error.
int wdb_users_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * user_name, const char * user_full_name, 
                     const char * user_home, int user_id, int user_uid_signed, const char * user_uuid, const char * user_groups, 
                     int user_group_id, int user_group_id_signed, double user_created, const char * user_roles, const char * user_shell, 
                     const char * user_type, const bool user_is_hidden, const bool user_is_remote, long user_last_login, 
                     int user_auth_failed_count, double user_auth_failed_timestamp, double user_password_last_set_time, 
                     int user_password_expiration_date, const char * user_password_hash_algorithm, int user_password_inactive_days,
                     int user_password_last_change, int user_password_max_days_between_changes, int user_password_min_days_between_changes,
                     const char * user_password_status, int user_password_warning_days_before_expiration, long process_pid, const char * host_ip,
                     const bool login_status, const char * login_type, const char * login_tty, const char * checksum, const bool replace);

// Save group info into DB.
int wdb_groups_save(wdb_t * wdb, const char * scan_id, const char * scan_time, long group_id, const char * group_name, 
                    const char * group_description, long group_id_signed, const char * group_uuid, const bool group_is_hidden, 
                    const char * group_users, const char * checksum, const bool replace);

// Insert group info tuple. Return 0 on success or -1 on error.
int wdb_groups_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, long group_id, const char * group_name, 
                      const char * group_description, long group_id_signed, const char * group_uuid, const bool group_is_hidden, 
                      const char * group_users, const char * checksum, const bool replace);

int wdb_syscollector_save2(wdb_t * wdb, wdb_component_t component, const char * payload);

// Save CIS-CAT scan results.
int wdb_ciscat_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, const char * profile, int pass, int fail, int error, int notchecked, int unknown, int score);

// Insert CIS-CAT results tuple. Return 0 on success or -1 on error.
int wdb_ciscat_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, const char * profile, int pass, int fail, int error, int notchecked, int unknown, int score);

// Delete old information from the 'ciscat_results' table
int wdb_ciscat_del(wdb_t * wdb, const char * scan_id);

wdb_t * wdb_init(const char * id);

void wdb_destroy(wdb_t * wdb);

void wdb_pool_append(wdb_t * wdb);

void wdb_pool_remove(wdb_t * wdb);

/**
 * @brief Duplicate the database pool
 *
 * Gets a copy of the database pool. This function fills the member "id" and
 * creates the mutex only.
 *
 * @return Pointer to a database list.
 */
wdb_t * wdb_pool_copy();

void wdb_close_all();

void wdb_commit_old();

void wdb_close_old();

int wdb_remove_database(const char * agent_id);

/**
 * @brief Checks and vacuums (if necessary) the databases in the DB pool.
 */
void wdb_check_fragmentation();

/**
 * @brief Function to execute one row of an SQL statement and save the result in a JSON array.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [out] status The status code of the statement execution. If NULL no value is written.
 * @param [in] column_mode It could be STMT_SINGLE_COLUMN if the query returns only one column,
 *                         or STMT_MULTI_COLUMN if the query returns more than one column.
 * @return JSON array with the statement execution results, NULL on error.
 */
cJSON* wdb_exec_row_stmt(sqlite3_stmt* stmt, int* status, bool column_mode);

/**
 * @brief Function to execute one row of an SQL statement and save the result in a single JSON array without column name like:
 *        ["column_value_1","column_value_2", ...]. The query should return only one column in every step.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [out] status The status code of the statement execution. If NULL no value is written.
 * @return JSON array with the statement execution results, NULL on error.
 */
cJSON* wdb_exec_row_stmt_single_column(sqlite3_stmt* stmt, int* status);

/**
 * @brief Function to execute one row of an SQL statement and save the result in a single JSON array with column name like:
 *        ["column_name_1":"column_value_1","column_name_2":"column_value_2", ...].
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [out] status The status code of the statement execution. If NULL no value is written.
 * @return JSON array with the statement execution results, NULL on error.
 */
cJSON* wdb_exec_row_stmt_multi_column(sqlite3_stmt* stmt, int* status);

/**
 * @brief Function to execute an SQL statement without a response.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_exec_stmt_silent(sqlite3_stmt* stmt);

/**
 * @brief Function to execute a SQL statement and save the result in a JSON array limited by size.
 *        Each step of the statement will be printed to know the size.
 *        The result of each step will be placed in returned result while fits.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [in] max_size Maximum size of the response.
 * @param [out] status The status code of the statement execution.
 *                     SQLITE_DONE means the statement is completed.
 *                     SQLITE_ROW means the statement has pending elements.
 *                     SQLITE_ERROR means an error occurred.
 * @param [in] column_mode It could be STMT_SINGLE_COLUMN if the query returns only one column,
 *                         or STMT_MULTI_COLUMN if the query returns more than one column.
 * @return JSON array with the statement execution results, NULL on error.
 */
cJSON* wdb_exec_stmt_sized(sqlite3_stmt* stmt, const size_t max_size, int* status, bool column_mode);

/**
 * @brief Function to execute a SQL statement and send the result via TCP socket.
 *        Each row of the SQL response will be sent in a different command.
 *        This method will continue until SQL_DONE or an error is obtained.
 *        This method could block if the receiver lasts longer in receiving the information.
 *        The block will timeout after the time defined in WDB_BLOCK_SEND_TIMEOUT_S.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [in] peer The peer where the result will be sent.
 * @return OS_SUCCESS on success.
 *         OS_INVALID on errors executing SQL statement.
 *         OS_SOCKTERR on errors handling the socket.
 *         OS_SIZELIM on error trying to fit the row response into the socket buffer.
 */
int wdb_exec_stmt_send(sqlite3_stmt* stmt, int peer);

/**
 * @brief Function to execute a SQL statement and save the result in a JSON array.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @return JSON array with the statement execution results. NULL On error.
 */
cJSON* wdb_exec_stmt(sqlite3_stmt* stmt);

/**
 * @brief Function to execute a SQL query and save the result in a JSON array.
 *
 * @param [in] db The SQL database to be queried.
 * @param [in] sql The SQL query.
 * @return JSON array with the query results. NULL On error.
 */
cJSON* wdb_exec(sqlite3* db, const char * sql);

// Execute SQL script into an database
int wdb_sql_exec(wdb_t *wdb, const char *sql_exec);

int wdb_close(wdb_t * wdb, bool commit);

/**
 * @brief Finalizes all the statements in cache for a specific database.
 *
 * @param wdb The database struct pointer.
 */
void wdb_finalize_all_statements(wdb_t * wdb);

wdb_t * wdb_pool_find_prev(wdb_t * wdb);

int wdb_stmt_cache(wdb_t * wdb, int index);

int wdb_parse(char * input, char * output, int peer);

sqlite3 * wdb_global_pre(void **wdb_ctx);
void wdb_global_post(void *wdb_ctx);

int wdb_parse_syscheck(wdb_t * wdb, wdb_component_t component, char * input, char * output);
int wdb_parse_syscollector(wdb_t * wdb, const char * query, char * input, char * output);

/**
 * @brief Parses a rootcheck command
 * Commands:
 * 1. delete: Deletes pm table
 * 2. save: Inserts the entry or updates if it already exists
 * @param wdb Database of an agent
 * @param input Buffer input
 * @param output Buffer output, on success responses are:
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

/**
 * @brief Parses a packages command
 * Commands:
 * 1. del: Deletes packages table
 * 2. save: Inserts the entry or updates if it already exists
 * 3. get: Obtain every package on the table.
 * @param wdb Database of an agent
 * @param input Buffer input
 * @param output Buffer output
 * */
int wdb_parse_packages(wdb_t * wdb, char * input, char * output);

/**
 * @brief Parses a hotfixes command
 * Commands:
 * 1. del: Deletes hotfixes table
 * 2. save: Inserts the entry or updates if it already exists
 * 3. get: Obtain every hotfix on the table.
 * @param wdb Database of an agent
 * @param input Buffer input
 * @param output Buffer output
 * */
int wdb_parse_hotfixes(wdb_t * wdb, char * input, char * output);

int wdb_parse_ports(wdb_t * wdb, char * input, char * output);

int wdb_parse_processes(wdb_t * wdb, char * input, char * output);

int wdb_parse_ciscat(wdb_t * wdb, char * input, char * output);

int wdb_parse_sca(wdb_t * wdb, char * input, char * output);


/**
 * @brief Function to parse get operation over the sys_osinfo database table.
 *
 * @param wdb The Global struct database.
 * @param output Buffer output, on success responses are:
 *        "ok <data>" -> If sql statement was processed.
 *        "err <error_message>" -> If sql statement wasn't processed.
 * @return -1 on error, and 0 on success.
 */
int wdb_parse_agents_get_sys_osinfo(wdb_t* wdb, char* output);


/**
 * @brief Function to parse set operation over the sys_osinfo database table.
 *
 * @param wdb The Global struct database.
 * @param input Buffer input
 * @param output Buffer output, on success responses are:
 *        "ok" -> If sql statement was processed.
 *        "err <error_message>" -> If sql statement wasn't processed.
 * @return -1 on error, and 0 on success.
 */
int wdb_parse_agents_set_sys_osinfo(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse generic dbsync message operation, and generate
 * a message to process in wazuh-db process.
 *
 * @param wdb The Global struct database.
 * @param input Buffer input
 * @param output Buffer output, on success responses are:
 *        "ok" -> If entry was processed
 *        "error" -> If entry wasn't processed.
 * @return -1 on error, and 0 on success.
 */
int wdb_parse_dbsync(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent insert request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_insert_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent name request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_name(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent data request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_data(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the labels request for a particular agent.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query in JSON format.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_get_agent_labels(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to get the groups integrity information in global.db.
 *
 * @param wdb The global struct database.
 * @param input String with 'hash'.
 * @param output Response of the query in JSON format.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_get_groups_integrity(wdb_t * wdb, char * input, char* output);

/**
 * @brief Function to recalculate the agent group hash in global.db.
 *
 * @param wdb The global struct database.
 * @param output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_recalculate_agent_group_hashes(wdb_t* wdb, char* output);

/**
 * @brief Function to get all the agent information.
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
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_set_agent_labels(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent keepalive request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_keepalive(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent connection status.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_connection_status(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent connection status.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_status_code(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent delete from agent table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_delete_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent name request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_agent_name(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the find agent request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String JSON with the agent name and ip.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_find_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the find group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_find_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the insert group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_insert_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select group from belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent id in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_group_belong(wdb_t *wdb, char *input, char *output);

/**
 *
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_delete_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select groups request.
 *
 * @param [in] wdb The global struct database.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_groups(wdb_t * wdb, char * output);

/**
 * @brief Function to parse the get group agents request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_get_group_agents(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the set agent groups request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_set_agent_groups(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to recalculate the agent group hash.
 *
 * @param [in] wdb The global struct database.
 * @param [in] agent_id Int with the agent id.
 * @param [in] sync_status String with the sync_status to be set.
 * @return WDBC_OK Success.
 *         WDBC_ERROR On error.
 */
int wdb_global_recalculate_agent_groups_hash(wdb_t* wdb, int agent_id, char* sync_status);

/**
 * @brief Function to recalculate the agent group hash whitout update sync_status field.
 *
 * @param [in] wdb The global struct database.
 * @param [in] agent_id Int with the agent id.
 * @return WDBC_OK Success.
 *         WDBC_ERROR On error.
 */
int wdb_global_recalculate_agent_groups_hash_without_sync_status(wdb_t* wdb, int agent_id, char * group);

/**
 * @brief Function to recalculate the agent group hash for all agents.
 *
 * @param [in] wdb The global struct database.
 * @return OS_SUCCESS Success.
 *         OS_INVALID On error.
 */
int wdb_global_recalculate_all_agent_groups_hash(wdb_t* wdb);

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
 * @brief Function to parse sync-agent-groups-get command data.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String in json format with last_id and sync_condition.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_sync_agent_groups_get(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse the disconnect-agents command data.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the time threshold before which consider an agent as disconnected and last id to continue.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_disconnect_agents(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse last_id get-all-agents.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with last_id.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_all_agents(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse the get-distinct-groups command data.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'last_group_hash'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_distinct_agent_groups(wdb_t* wdb, char *input, char* output);

/**
 * @brief Function to parse the reset agent connection status request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the 'sync_status'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_reset_agents_connection(wdb_t * wdb, char* input, char * output);

/**
 * @brief Function to parse the get agents by connection status request.
 *
 * @param wdb The global struct database.
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'last_id' and 'connection_status'.
 * @param [out] output Response of the query in JSON format.
 * @retval 0 Success: Response contains the value.
 * @retval -1 On error: Response contains details of the error.
 */
int wdb_parse_global_get_agents_by_connection_status(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse the global backup request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the backup command.
 * @param [out] output Response of the query in JSON format.
 * @retval  0 Success: Response contains the value.
 * @retval -1 On error: Response contains details of the error.
 */
int wdb_parse_global_backup(wdb_t** wdb, char* input, char* output);

/**
 * @brief Function to parse the global get backup.
 *
 * @param [out] output Response of the query in JSON format.
 * @retval  0 Success: Response contains a list of the available backups.
 * @retval -1 On error: Response contains details of the error.
 */
int wdb_parse_global_get_backup(char* output);

/**
 * @brief Function to parse the global restore request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the snapshot to restore. If not present, the more recent will be used.
 * @param [out] output Response of the query in JSON format.
 * @retval  0 Success: Response contains 'ok'.
 * @retval -1 On error: Response contains details of the error.
 */
int wdb_parse_global_restore_backup(wdb_t** wdb, char* input, char* output);

/**
 * @brief Function to create a backup of the global.db.
 *
 * @param [in] wdb The global struct database.
 * @param [out] output Response of the query.
 * @param [in] tag Adds extra information to snapshot file name, used in case of upgrades and restores.
 * @retval  0 Success: Backup created successfully.
 * @retval -1 On error: The backup creation failed.
 */
int wdb_global_create_backup(wdb_t* wdb, char* output, const char* tag);

/**
 * @brief Function to delete old backups in case the amount exceeds the max_files limit.
 *
 * @retval  0 Success: The method exited without errors.
 * @retval -1 On error: The method failed in reading the backup folder.
 */
int wdb_global_remove_old_backups();

/**
 * @brief Function to get a list of the available backups of global.db.
 *
 * @retval cJSON* Success: The list of all snapshots found, or empty if none was found.
 * @retval NULL On error: The list of snapshots couldn't be retrieved.
 */
cJSON* wdb_global_get_backups();

/**
 * @brief Method to restore a backup of global.db.
 *
 * @param [in] wdb The global struct database.
 * @param [in] snapshot The backup file name to be restored. If not present, the last one will be used.
 * @param [in] save_pre_restore_state If FALSE or not present, the database will be overwritten with the snapshot. If TRUE,
 *                                    the database will be saved before restoring the snapshot.
 * @param [out] output A message related to the result of the operation.
 * @retval  0 Success: Backup restored successfully.
 * @retval -1 On error: The backup couldn't be restored.
 */
int wdb_global_restore_backup(wdb_t** wdb, char* snapshot, bool save_pre_restore_state, char* output);

/**
 * @brief Function to check if there is at least one backup configuration node enabled.
 *
 * @retval true If there is at least one backup enabled, false otherwise.
 */
bool wdb_check_backup_enabled();

/**
 * @brief Method to get the most recent global.db backup time and name
 *
 * @param most_recent_backup_name [out] The name of the most recent backup. Must be freed by the caller, ignored if NULL.
 * @retval Last modification time of the most recent backup on success, OS_INVALID on error.
 */
time_t wdb_global_get_most_recent_backup(char **most_recent_backup_name);

/**
 * @brief Method to get oldest global.db backup time and name
 *
 * @param oldest_backup_name [out] The name of the oldest backup. Must be freed by the caller, ignored if NULL.
 * @retval Last modification time of the oldest backup on success, OS_INVALID on error.
 */
time_t wdb_global_get_oldest_backup(char **oldest_backup_name);
// Functions for database integrity

int wdbi_checksum(wdb_t * wdb, wdb_component_t component, os_sha1 hexdigest);

int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest);

int wdbi_delete(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, const char * tail);

void wdbi_report_removed(const char* agent_id, wdb_component_t component, sqlite3_stmt* stmt);

/**
 * @brief Updates the timestamps and counters of a component from sync_info table. It should be called when
 *        the syncronization with the agents is in process, or the checksum sent to the manager is not the same than
 *        the one calculated locally.
 *
 *        The 'legacy' flag calls internally to a different SQL statement, to avoid an overflow in the n_attempts column.
 *        It happens because the old agents call this method once per row, and not once per syncronization cycle.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] component An enumeration member that was previously added to the table.
 * @param [in] timestamp The syncronization timestamp to store in the table.
 * @param [in] last_agent_checksum The last global checksum received from the agent.
 * @param [in] manager_checksum Checksum of the last calculated component on the manager to be stored.
 * @param [in] legacy This flag is set to TRUE for agents with an old syscollector syncronization process, and FALSE otherwise.
 */
void wdbi_update_attempt(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 last_agent_checksum, os_sha1 manager_checksum, bool legacy);

/**
 * @brief Updates the timestamps and counters of a component from sync_info table. It should be called when
 *        the syncronization with the agents is complete, or the checksum sent to the manager is the same than
 *        the one calculated locally.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] component An enumeration member that was previously added to the table.
 * @param [in] timestamp The syncronization timestamp to store in the table.
 * @param [in] last_agent_checksum The last global checksum received from the agent.
 * @param [in] manager_checksum Checksum of the last calculated component on the manager to be stored.
 */
void wdbi_update_completion(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 last_agent_checksum, os_sha1 manager_checksum);

/**
 * @brief Get the last stored checksum of a component on the manager
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param manager_checksum os_sha1 where the last checksum is returned
 */
int wdbi_get_last_manager_checksum(wdb_t *wdb, wdb_component_t component, os_sha1 manager_checksum);

void wdbi_set_last_completion(wdb_t * wdb, wdb_component_t component, long timestamp);

int wdbi_check_sync_status(wdb_t *wdb, wdb_component_t component);

/**
 * @brief Method to obtain and cache the hash of the whole group_local_hash column in agent table.
 *        If the cache is empty, the global group hash is calculated and stored.
 *
 * @param wdb The DB pointer structure.
 * @param hexdigest Variable to return the global group hash.
 * @return int OS_SUCCESS if the hexdigest variable was written with the global group hash value, OS_INVALID otherwise.
 */
int wdb_get_global_group_hash(wdb_t * wdb, os_sha1 hexdigest);

/**
 * @brief Method to perform all the required operations over the global group hash cache.
 *
 * @param operation      WDB_GLOBAL_GROUP_HASH_READ : OS_INVALID if there is no value in cache. OS_SUCCESS if a value was found and stored in hexdigest
 *                       WDB_GLOBAL_GROUP_HASH_WRITE: OS_SUCCESS after writting the hexdigest value in global_group_hash.
 *                       WDB_GLOBAL_GROUP_HASH_CLEAR: OS_SUCCESS after clearing the global group hash cache.
 * @param hexdigest Input/Output variable, see "operation".
 * @return int OS_INVALID in case of an unsupported "operation". See "operation" for the rest of cases.
 */
int wdb_global_group_hash_cache(wdb_global_group_hash_operations_t operation, os_sha1 hexdigest);

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
 * @brief Function to recreate Global DB in case of an upgrading an old version.
 *
 * @param [in] wdb The global.db database to backup.
 * @return wdb The new empty global.db database on success or NULL on error
 */
wdb_t * wdb_recreate_global(wdb_t *wdb);

/**
 * @brief Check if the db version is older than 3.10
 *
 * This is a hacky way to check if the database version is older than 3.10
 * For newer versions of the db the table "agent" must have a tuple with id=0(manager) and last_keepalive=9999/12/31 23:59:59 UTC.
 * If this value is missing it means that the db is older than 3.10 or is corrupt
 *
 * @return Db version is older than 3.10.
 * @retval 1 the db is older than 3.10
 * @retval 0 the db is newer than 3.10.
 * @retval 0 The table "agent" is missing or an error occurred.
 */
bool wdb_is_older_than_v310(wdb_t *wdb);

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
 * @param [in] action Integrity check action: INTEGRITY_CHECK_GLOBAL, INTEGRITY_CHECK_LEFT or INTEGRITY_CHECK_RIGHT.
 * @param [in] payload Operation arguments in JSON format.
 * @pre payload must contain strings "id", "begin", "end" and "checksum", and optionally "tail".
 * @retval INTEGRITY_SYNC_CKS_OK   Success: checksum matches.
 * @retval INTEGRITY_SYNC_CKS_FAIL Success: checksum does not match.
 * @retval INTEGRITY_SYNC_NO_DATA  Success: no files were found in this range.
 * @retval INTEGRITY_SYNC_ERR      On error.
 */

integrity_sync_status_t wdbi_query_checksum(wdb_t * wdb, wdb_component_t component, dbsync_msg action, const char * payload);

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
 * @brief Enables foreign keys usage into the specified database.
 *
 * @param [in] db Pointer to an open database.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdb_enable_foreign_keys(sqlite3 *db);

/**
*  @brief Calculates SHA1 hash from a NULL terminated string array.
*
* @param [in] strings_to_hash NULL Terminated array with strings to hash
* @param [out] hexdigest Result
*/
 int wdbi_array_hash(const char ** strings_to_hash, os_sha1 hexdigest);

/**
*  @brief Calculates SHA1 hash from a NULL terminated set of strings.
*
* @param [in] ... NULL Terminated list of strings
* @param [out] hexdigest Result
*/
 int wdbi_strings_hash(os_sha1 hexdigest, ...);

/**
 * @brief Function to get a MITRE technique's name.
 *
 * @param [in] wdb The MITRE struct database.
 * @param [in] id MITRE technique's ID.
 * @param [out] output MITRE technique's name.
 * @retval 1 Success: name found on MITRE database.
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
 * @param [in] connection_status The agent's connection status.
 * @param [in] sync_status The agent's synchronization status in cluster.
 * @param [in] group_config_status The agent's shared configuration synchronization status.
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
                                    const char *connection_status,
                                    const char *sync_status,
                                    const char *group_config_status);

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
 * @param [in] connection_status The agent's connection status.
 * @param [in] sync_status The value of sync_status
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_keepalive(wdb_t *wdb, int id, const char *connection_status, const char *sync_status);

/**
 * @brief Function to update an agent connection status and the synchronization status.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID.
 * @param [in] connection_status The connection status to be set.
 * @param [in] sync_status The value of sync_status.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_connection_status(wdb_t *wdb, int id, const char* connection_status, const char *sync_status, int status_code);

/**
 * @brief Function to update an agent status code and the synchronization status.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID.
 * @param [in] status_code The status code to be set.
 * @param [in] version The agent version to be set.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_status_code(wdb_t *wdb, int id, int status_code, const char *version, const char *sync_status);

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
 * @brief Function to update the agent's groups_hash column. It reads the group column, calculates and stores its hash
 *        but if the group column is NULL, the method returns without modifying groups_hash.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] groups_string The comma separated groups string to hash and store in groups_hash column. If not set,
 *                           it will be read from 'group' column.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_groups_hash(wdb_t* wdb, int agent_id, char* groups_string);

/**
 * @brief Function to update the agent's groups_hash column for all agents. It gets all agents and calls
 *        wdb_global_update_agent_groups_hash() for each one.
 *
 * @param [in] wdb The Global struct database.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_adjust_v4(wdb_t* wdb);

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
 * @brief Function to get groups of a specified agent from the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id_agent The agent id.
 * @return JSON with agent groups on success. NULL on error.
 */
cJSON* wdb_global_select_group_belong(wdb_t *wdb, int id_agent);

/**
 * @brief Function to insert an agent to the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id_group The group id.
 * @param [in] id_agent The agent id.
 * @param [in] priority The group priority.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent, int priority);

/**
 * @brief Function to remove an agent-group tuple from the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id_group The group id.
 * @param [in] id_agent The agent id.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_tuple_belong(wdb_t *wdb, int id_group, int id_agent);

/**
 * @brief Function to check if a group is empty.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns cJSON* with agents id.
 */
cJSON* wdb_is_group_empty(wdb_t *wdb, char* group_name);

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
 * @brief Function to get all agents that belong to a group
 *
 * @param [in] wdb The Global struct database.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @param [in] group_name The name of the group to get the agents from
 * @param [in] last_agent_id ID where to start querying.
 * @retval JSON with agents IDs on success, NULL on error.
 */
cJSON* wdb_global_get_group_agents(wdb_t *wdb,  wdbc_result* status, char* group_name, int last_agent_id);

/**
 * @brief Function to find and set the correct sync status value
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] requested_sync_status The value of sync_status
*/
char *wdb_global_validate_sync_status(wdb_t *wdb, int id, const char *requested_sync_status);

/**
 * @brief Function to get sync_status of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @return The value of sync_status.
 */
char * wdb_global_get_sync_status(wdb_t *wdb, int id);

/**
 * @brief Function to update sync_status of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] sync_status The value of sync_status
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
 * @brief Gets each agent matching the sync condition and all their groups.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents and groups.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] condition The condition of the agents to be requested.
 *              WDB_GROUP_SYNC_STATUS for agents tagged as sync_req,
 *              WDB_GROUP_CKS_MISMATCH for agents with difference between the CKS in the master and the worker.
 * @param [in] last_agent_id ID where to start querying.
 * @param [in] set_synced Indicates if the obtained groups must be set as synced.
 * @param [in] get_hash Indicates if the response must append the group_hash once all the groups have been obtained.
 * @param [in] agent_registration_delta Minimum amount of seconds since the registration time for the agent to be included in the result.
 * @param [out] output A cJSON pointer where the response is written. Must be de-allocated by the caller.
 * @return wdbc_result to represent if all agents has being obtained.
 */
wdbc_result wdb_global_sync_agent_groups_get(wdb_t* wdb,
                                             wdb_groups_sync_condition_t condition,
                                             int last_agent_id,
                                             bool set_synced,
                                             bool get_hash,
                                             int agent_registration_delta,
                                             cJSON** output);

/**
 * @brief Add global group hash to JSON response.
 *
 * @param wdb The Global struct database.
 * @param response JSON response to fill with global group hash.
 * @param response_size Current size of JSON response.
 * @return int result to represent if global hash has being added to JSON response.
 */
int wdb_global_add_global_group_hash_to_response(wdb_t *wdb, cJSON** response, size_t response_size);

/**
 * @brief Function to update group_sync_status of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] sync_status The value of sync_status
 * @return OS_SUCCESS On success. OS_ERROR On error.
 */
int wdb_global_set_agent_groups_sync_status(wdb_t *wdb,
                                            int id,
                                            const char* sync_status);

/**
 * @brief It gets all the groups of an agent and returns them in a comma sepparated string
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to obtain the group.
 * @return char* String with the groups of the agent in CSV format. Must be de-allocated by the caller. It returns NULL on error.
 */
char* wdb_global_calculate_agent_group_csv(wdb_t *wdb, int id);

/**
 * @brief Sets the group information in the agent table.
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to set the information.
 * @param [in] csv String with all the groups sepparated by comma to be inserted in the group column.
 * @param [in] hash Hash calculus from the csv string to be inserted in the group_hash column.
 * @param [in] sync_status Tag of the sync status to be inserted in the group_sync_status column.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_global_set_agent_group_context(wdb_t *wdb, int id, char* csv, char* hash, char* sync_status);

/**
 * @brief Sets the group information in the agent table.
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to set the information.
 * @param [in] csv String with all the groups sepparated by comma to be inserted in the group column.
 * @param [in] hash Hash calculus from the csv string to be inserted in the group_hash column.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_global_set_agent_group_hash(wdb_t *wdb, int id, char* csv, char* hash);

/**
 * @brief Verifies if at least one entry in the Global DB has the group_sync_status as "syncreq".
 *        If not, it compares a received hash that represents the group column against a calculated hash.
 *
 * @param wdb The Global struct database.
 * @param hash Received group column hash.
 * @return cJSON* Returns a cJSON object with the groups integrity status or NULL on error.
 */
cJSON* wdb_global_get_groups_integrity(wdb_t *wdb, os_sha1 hash);

/**
 * @brief Gets the maximum priority of the groups of an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to obtain the priority.
 * @return Numeric representation of the group priority.
 */
int wdb_global_get_agent_max_group_priority(wdb_t *wdb, int id);

/**
 * @brief Writes groups to an agent.
 *        If the group doesn´t exists it creates it.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to add new groups.
 * @param [in] j_groups JSON array with all the groups of the agent.
 * @param [in] priority Initial priority to insert the groups.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_global_assign_agent_group(wdb_t *wdb, int id, cJSON* j_groups, int priority);

/**
 * @brief Deletes groups of an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to remove the groups.
 * @param [in] j_groups JSON array with all the groups to remove from the agent.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_global_unassign_agent_group(wdb_t *wdb, int id, cJSON* j_groups);

/**
 * @brief Sets default group to an agent if it doesn't have any.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id ID of the agent to set default group.
 * @return wdbc_result representing the status of the command.
 */
int wdb_global_if_empty_set_default_agent_group(wdb_t *wdb, int id);

/**
 * @brief Returns the number of groups that are assigned to an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] agent_id ID of the agent to get the groups number from.
 * @return int Returns the groups number or -1 on error.
 */
int wdb_global_groups_number_get(wdb_t *wdb, int agent_id);

/**
 * @brief Verifies that the group name satisfies with a predefined pattern.
 *
 * @param group_name Group name to be validated.
 * @return w_err_t OS_SUCCESS if valid. OS_INVALID otherwise.
 */
w_err_t wdb_global_validate_group_name(const char *group_name);

/**
 * @brief Verifies that the number of groups to be assigned is less or equal to 128 and
 *        there's no group longer than 255 characters nor contains a comma as part of its name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] j_groups JSON array with all the groups to be assigned to an agent.
 * @param [in] agent_id ID of the agent to add new groups.
 * @return wdbc_result representing the status of the command.
 */
w_err_t wdb_global_validate_groups(wdb_t *wdb, cJSON *j_groups, int agent_id);

/**
 * @brief Sets the belongship af a set of agents.
 *          If any of the groups doesn´t exist, this command creates it.
 * @param [in] wdb The Global struct database.
 * @param [in] mode The mode in which the write will be performed.
 *               WDB_GROUP_OVERRIDE The existing groups will be overwritten.
                 WDB_GROUP_APPEND The existing groups are conserved and new ones are added.
                 WDB_GROUP_EMPTY_ONLY The groups are written only if the agent doesn´t have any group.
 * @param [in] sync_status The sync_status tag used to insert the groups.
 * @param [in] j_agents_group_info JSON structure with all the agent_ids and the groups to insert.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result wdb_global_set_agent_groups(wdb_t *wdb, wdb_groups_set_mode_t mode, char* sync_status, cJSON* j_agents_group_info);

/**
 * @brief Function to get the information of a particular agent stored in Wazuh DB.
 *
 * @param wdb The Global struct database.
 * @param id Agent id.
 * @retval JSON with agent information on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agent_info(wdb_t *wdb, int id);

/**
 * @brief Gets every agent ID.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_all_agents(wdb_t *wdb, int last_agent_id, wdbc_result* status);

/**
 * @brief Gets every agent ID with context.
 *        Response is send by elements.
 *        One call of this function send all agents.
 *
 * @param [in] wdb The Global struct database.
 * @retval OS_SUCCESS on success.
 * @retval OS_INVALID on error.
 */
int wdb_global_get_all_agents_context(wdb_t *wdb);

/**
 * @brief Checks the given ID is in the agent table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] agent_id ID to check.
 * @retval 0 if the ID was not found.
 * @retval 1 if the ID was found.
 * @retval -1 on error.
 */
int wdb_global_agent_exists(wdb_t *wdb, int agent_id);

/**
 * @brief Function to reset connection_status column of every agent (excluding the manager).
 *        If connection_status is pending or connected it will be changed to disconnected.
 *        If connection_status is disconnected or never_connected it will not be changed.
 *        It also set the 'sync_status' with the specified value.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] sync_status The value of sync_status.
 * @return 0 On success. -1 On error.
 */
int wdb_global_reset_agents_connection(wdb_t *wdb, const char *sync_status);

/**
 * @brief Function to get the id of every agent with a specific connection_status.
 *        Response is prepared in one chunk, if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE
 *        parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [in] connection_status Connection status of the agents requested.
 * @param [in] node_name Cluster node name
 * @param [in] limit Limits the number of rows returned by the query.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, const char* node_name, int limit, wdbc_result* status);

/**
 * @brief Gets all the agents' IDs (excluding the manager) that satisfy the keepalive condition to be disconnected.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [in] sync_status The value of sync_status.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agents_to_disconnect(wdb_t *wdb, int last_agent_id, int keep_alive, const char *sync_status, wdbc_result* status);

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

/**
 * @brief Returns a JSON array containing the group and group_hash assigned to all agents,
 *        if two agents have the same group assigned it is only included once
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_hash Group hash where to start querying.
 * @param [out] status wdbc_result to represent if all group/group_hash has being obtained or any error occurred.
 * @retval JSON with group/group_hash on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_distinct_agent_groups(wdb_t *wdb, char *group_hash, wdbc_result* status);

/**
 * @brief Function to insert or update rows with a dynamic query based on metadata.
 * Its necessary to have the table PKs well.
 *
 * @param wdb The Global struct database.
 * @param kv_value Table metadata to build dynamic queries.
 * @param data JSON object containing delta information.
 * @retval true when the database insertion is executed successfully.
 * @retval false on error.
 */
bool wdb_upsert_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data);

/**
 * @brief Function to delete rows with a dynamic query based on metadata.
 * Its necessary to have the table PKs well.
 *
 * @param wdb The Global struct database.
 * @param kv_value Table metadata to build dynamic queries.
 * @param data JSON object containing delta information.
 * @retval true when the database delete is executed successfully.
 * @retval false on error.
 */
bool wdb_delete_dbsync(wdb_t * wdb, struct kv const *kv_value, cJSON *data);

/**
 * @brief Function to parse the insert upgrade request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param command Command to be insert in task
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade(wdb_t* wdb, const cJSON *parameters, const char *command, char* output);

/**
 * @brief Function to parse the upgrade_get_status request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_get_status(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the upgrade_update_status request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_update_status(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the upgrade_result request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_result(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the upgrade_cancel_tasks request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_cancel_tasks(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the set_timeout request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_set_timeout(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the delete_old request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_delete_old(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * Update old tasks with status in progress to status timeout
 * @param wdb The task struct database
 * @param now Actual time
 * @param timeout Task timeout
 * @param next_timeout Next task in progress timeout
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_set_timeout_status(wdb_t* wdb, time_t now, int timeout, time_t *next_timeout);

/**
 * Delete old tasks from the tasks DB
 * @param wdb The task struct database
 * @param timestamp Deletion limit time
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_delete_old_entries(wdb_t* wdb, int timestamp);

/**
 * Insert a new task in the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task will be executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the message comes from.
 * @param command Command to be executed in the agent.
 * @return ID of the task recently created when succeed, <=0 otherwise.
 * */
int wdb_task_insert_task(wdb_t* wdb, int agent_id, const char *node, const char *module, const char *command);

/**
 * Get the status of an upgrade task from the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param status String where the status of the task will be stored.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wdb_task_get_upgrade_task_status(wdb_t* wdb, int agent_id, const char *node, char **status);

/**
 * Update the status of a upgrade task in the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param status New status of the task.
 * @param error Error string of the task in case of failure.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wdb_task_update_upgrade_task_status(wdb_t* wdb, int agent_id, const char *node, const char *status, const char *error);

/**
 * Cancel the upgrade tasks of a given node in the tasks DB.
 * @param wdb The task struct database
 * @param node Node that executed the upgrades.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wdb_task_cancel_upgrade_tasks(wdb_t* wdb, const char *node);

/**
 * Get task by agent_id and module from the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the command comes from.
 * @param command String where the command of the task will be stored.
 * @param status String where the status of the task will be stored.
 * @param error String where the error message of the task will be stored.
 * @param create_time Integer where the create_time of the task will be stored.
 * @param last_update_time Integer where the last_update_time of the task will be stored.
 * @return task_id when succeed, < 0 otherwise.
 * */
int wdb_task_get_upgrade_task_by_agent_id(wdb_t* wdb, int agent_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time);

/**
 * @brief Delete entries by pk.
 *
 * @param wdb Database node.
 * @param stmt The SQL statement to be executed.
 * @param pk_value Primary key value of the element to be deleted.
 */
void wdbi_remove_by_pk(wdb_t *wdb, wdb_component_t component, const char * pk);

// Finalize a statement securely
#define wdb_finalize(x) { if (x) { sqlite3_finalize(x); x = NULL; } }

/**
 * Get cache stmt cached for specific query.
 * @param wdb The task struct database
 * @param query is the query to be executed.
 * @return Pointer to the statement already cached. NULL On error.
 * */

sqlite3_stmt * wdb_get_cache_stmt(wdb_t * wdb, char const *query);

/**
 * @brief Method to read the internal wazuh-db configuration.
 *
 * @return cJSON* Returns a cJSON object with the configuration requested.
 */
cJSON* wdb_get_internal_config();

/**
 * @brief Method to read the wdb configuration section.
 *
 * @return cJSON* Returns a cJSON object with the configuration requested.
 */
cJSON* wdb_get_config();

/**
 * @brief Check and execute the input request
 *
 * @param request message received from api
 * @param output the response to send
 */
void wdbcom_dispatch(char* request, char* output);


/**
 * @brief Set the synchronous mode of the SQLite database session.
 *
 * This function sets the synchronous mode of the SQLite database session to control how
 * and when changes made to the database are written to disk. It executes the necessary
 * SQL statements to set the synchronous mode.
 *
 * @param[in] wdb The database structure.
 * @return Returns 0 on success or -1 if an error occurs while setting the synchronous mode.
 */
int wdb_set_synchronous_normal(wdb_t * wdb);

#endif

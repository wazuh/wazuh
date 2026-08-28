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
#include "sqlite3.h"
#include "syscheck_op.h"
#include "wazuhdb_op.h"
#include "regex_op.h"
#include "global-config.h"

#define WDB_MAX_COMMAND_SIZE    512
#define WDB_MAX_RESPONSE_SIZE   OS_MAXSTR-WDB_MAX_COMMAND_SIZE

#define AGENT_CS_NEVER_CONNECTED "never_connected"
#define AGENT_CS_PENDING         "pending"
#define AGENT_CS_ACTIVE          "active"
#define AGENT_CS_DISCONNECTED    "disconnected"

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

typedef enum wdb_stmt {
    WDB_STMT_GLOBAL_INSERT_AGENT,
    WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION,
    WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP,
    WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE,
    WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE,
    WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE_KEEPALIVE,
    WDB_STMT_GLOBAL_DELETE_AGENT,
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
    WDB_STMT_GLOBAL_GET_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT,
    WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_AGENT_EXISTS,
    // Generic task statements
    WDB_STMT_TASK_CREATE,
    WDB_STMT_TASK_GET_PENDING,
    WDB_STMT_TASK_MARK_DELIVERED,
    WDB_STMT_TASK_CLEANUP_EXPIRED,
    WDB_STMT_TASK_DELETE_OLD,
    // Manager task statements
    WDB_STMT_MANAGER_TASK_FIND_PENDING_BY_AGENT,
    WDB_STMT_MANAGER_TASK_COUNT_PENDING_BY_TYPE,
    WDB_STMT_MANAGER_TASK_INSERT,
    WDB_STMT_MANAGER_TASK_SELECT_CLAIMABLE,
    WDB_STMT_MANAGER_TASK_CLAIM,
    WDB_STMT_MANAGER_TASK_FIND_COMPETING_PENDING,
    WDB_STMT_MANAGER_TASK_INHERIT_COUNTERS,
    WDB_STMT_MANAGER_TASK_SUPERSEDE,
    WDB_STMT_MANAGER_TASK_REQUEUE,
    WDB_STMT_MANAGER_TASK_SET_RESULT,
    WDB_STMT_MANAGER_TASK_GET,
    WDB_STMT_MANAGER_TASK_GET_BY_AGENT,
    WDB_STMT_MANAGER_TASK_POLL_DUE,
    WDB_STMT_MANAGER_TASK_SELECT_CLAIMED_BY_OWNER,
    WDB_STMT_MANAGER_TASK_SELECT_CLAIMED_ANY,
    WDB_STMT_MANAGER_TASK_LIST_BY_TYPE,
    WDB_STMT_MANAGER_TASK_LIST_BY_TYPE_STATUS,
    WDB_STMT_MANAGER_TASK_COUNT_BY_TYPE_STATUS,
    WDB_STMT_MANAGER_TASK_PENDING_TYPES,
    WDB_STMT_MANAGER_TASK_FAIL_BY_TYPE,
    WDB_STMT_PRAGMA_JOURNAL_WAL,
    WDB_STMT_PRAGMA_ENABLE_FOREIGN_KEYS,
    WDB_STMT_PRAGMA_SYNCHRONOUS_NORMAL,
    WDB_STMT_PRAGMA_SYNCHRONOUS_FULL,
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
#include "wdb_pool.h"

extern char *schema_global_sql;
extern char *schema_task_manager_sql;
extern _Config gconfig;

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

/**
 * @brief Open task database and store in DB poll.
 *
 * It is opened every time a query to Task database is done.
 *
 * @return wdb_t* Database Structure that store task database or NULL on failure.
 */
wdb_t * wdb_open_tasks();

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
 * @brief Reads the SQLite PRAGMA user_version from the database header.
 * @param wdb Database connection.
 * @param[out] version The current user_version value.
 * @return OS_SUCCESS or OS_INVALID.
 */
int wdb_user_version_get(wdb_t *wdb, int *version);

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

/* Create global database */
int wdb_create_global(const char *path);

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source);

/**
 * @brief Run every statement of an embedded SQL schema against an open database.
 *
 * Applying a schema whose statements are all IF NOT EXISTS is idempotent, so this may be called
 * on an existing database to pick up tables added by a later release. It cannot alter a table
 * that already exists.
 *
 * @param[in] db Open database handle.
 * @param[in] source Schema text, as embedded by embed_sql.cmake.
 * @return OS_SUCCESS on success, OS_INVALID if any statement failed to prepare or step.
 */
int wdb_apply_schema(sqlite3 *db, const char *source);

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

wdb_t * wdb_init(const char * id);

void wdb_destroy(wdb_t * wdb);

void wdb_close_all();

void wdb_commit_old();

void wdb_close_old();

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

int wdb_stmt_cache(wdb_t * wdb, int index);

int wdb_parse(char * input, char * output, int peer);

sqlite3 * wdb_global_pre(void **wdb_ctx);
void wdb_global_post(void *wdb_ctx);

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

/**
 * @brief Run checksum of the whole result of an already prepared statement
 *
 * @param[in] wdb Database node.
 * @param[in] stmt Statement to be executed already prepared.
 * @param[out] hexdigest
 * @retval 1 On success.
 * @retval 0 If no items were found.
 */
int wdb_calculate_stmt_checksum(wdb_t * wdb, sqlite3_stmt * stmt, os_sha1 hexdigest);

/**
 * @brief Function to upgrade Global DB to the latest version.
 *
 * @param [in] wdb The global.db database to upgrade.
 * @return wdb The global.db database updated on success.
 */
wdb_t * wdb_upgrade_global(wdb_t *wdb);

/**
 * @brief Enables foreign keys usage into the specified database.
 *
 * @param [in] db Pointer to an open database.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdb_enable_foreign_keys(sqlite3 *db);

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
 * @brief Function to update an agent version data.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID.
 * @param [in] os_name The agent's operating system name.
 * @param [in] os_version The agent's operating system version.
 * @param [in] os_major The agent's operating system major version.
 * @param [in] os_minor The agent's operating system minor version.
 * @param [in] os_type The agent's operating system family (linux, windows, unix, ...).
 * @param [in] os_platform The agent's operating system platform.
 * @param [in] os_arch The agent's operating system architecture.
 * @param [in] version The agent's version.
 * @param [in] agent_ip The agent's IP address.
 * @param [in] connection_status The agent's connection status.
 * @param [in] sync_status The agent's synchronization status in cluster.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_version(wdb_t *wdb,
                                    int id,
                                    const char *os_name,
                                    const char *os_version,
                                    const char *os_major,
                                    const char *os_minor,
                                    const char *os_type,
                                    const char *os_platform,
                                    const char *os_arch,
                                    const char *version,
                                    const char *agent_ip,
                                    const char *connection_status,
                                    const char *sync_status);

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
 * @param [in] connection_status The connection status to be set. When not NULL, the last keepalive
 *                               is stamped and the disconnection time is reset as well.
 * @param [in] sync_status The value of sync_status.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_status_code(wdb_t *wdb, int id, int status_code, const char *version, const char *connection_status, const char *sync_status);

/**
 * @brief Function to delete an agent from the agent table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_agent(wdb_t *wdb, int id);

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
 * @param [in] create_agent_name If not null and the agent doesn't exist, it will be created with the given name.
 * @return wdbc_result representing the status of the command.
 */
wdbc_result
wdb_global_assign_agent_group(wdb_t* wdb, int id, cJSON* j_groups, int priority, const char* create_agent_name);

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
 * @brief Cleanup compiled regex for group name validation (for testing)
 */
void wdb_global_validate_group_name_cleanup(void);

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
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, wdbc_result* status);

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
 * @brief Function to parse the task create request.
 *
 * @param [in] wdb The task struct database.
 * @param parameters JSON with the parameters (task_id, agent_id, task_type, payload)
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
/* Manager tasks */

/**
 * @brief Largest page a manager task listing will return.
 *
 * Every response travels through the same fixed WDBOUTPUT_SIZE buffer, which silently truncates,
 * so the paged listings cap their own page size rather than trusting the caller's. At roughly
 * 200 bytes per entry this leaves the response about a third full at worst.
 */
#define WDB_MANAGER_TASK_PAGE_SIZE 100

/**
 * @brief Outcome of a manager task queue operation.
 *
 * Values start at 1 so that none of them can be mistaken for OS_SUCCESS or OS_INVALID.
 */
typedef enum manager_task_result_t {
    WDB_MANAGER_TASK_CREATED = 1,   ///< A new row was inserted.
    WDB_MANAGER_TASK_COALESCED,     ///< A pending row for the same agent and type already existed.
    WDB_MANAGER_TASK_COLLIDED,      ///< The task id is already present.
    WDB_MANAGER_TASK_QUEUE_FULL,    ///< The pending set for this type is at its admission bound.
    WDB_MANAGER_TASK_REQUEUED,      ///< The row went back to pending.
    WDB_MANAGER_TASK_SUPERSEDED     ///< A pending row had taken this row's slot; it was retired.
} manager_task_result_t;

/**
 * @brief Everything needed to create one manager task.
 *
 * Passed as a struct rather than as an argument list so that a task type needing a new field
 * does not churn every call site. Per-type policy (coalesce, max_pending) is carried here
 * because the dispatcher holds it as data in its handler registry; wazuh-db has no notion of
 * which task types exist.
 */
typedef struct wdb_manager_task_create_t {
    const char *task_id;        ///< 64 hex characters, derived per type.
    const char *task_type;      ///< Opaque to wazuh-db.
    const char *payload;        ///< The consumer's request body verbatim.
    const char *agent_id;       ///< NULL for tasks with no agent subject.
    const char *schedule_id;    ///< NULL unless spawned by a schedule.
    long long scheduled_run_at; ///< 0 unless spawned by a schedule.
    long long create_time;
    long long next_attempt_at;  ///< Falls back to create_time when unset.
    bool coalesce;              ///< Fold into an existing pending row for the same agent and type.
    int max_pending;            ///< 0 for unbounded, else refuse once the pending set is this large.
} wdb_manager_task_create_t;

/**
 * @brief Everything needed to return one manager task to the pending state.
 */
typedef struct wdb_manager_task_requeue_t {
    const char *task_id;
    const char *task_type;      ///< Only read when coalesce is set.
    const char *agent_id;       ///< Only read when coalesce is set.
    const char *last_error;     ///< May be NULL.
    long long next_attempt_at;
    int attempts;
    int defer_count;
    bool coalesce;
} wdb_manager_task_requeue_t;

/**
 * @brief Create a manager task, applying the per-type coalescing and admission policies.
 *
 * Commits before returning, so a successful reply is a durability acknowledgement.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task Task to create.
 * @param[out] surviving_task_id Set to the id of the row the caller should track: the new row,
 *             the row it coalesced into, or the row it collided with. Caller frees. May be NULL.
 * @return A manager_task_result_t value, or OS_INVALID on error.
 */
int wdb_manager_task_create(wdb_t *wdb, const wdb_manager_task_create_t *task, char **surviving_task_id);

/**
 * @brief Claim the next eligible task of one type for a lane.
 *
 * Commits before returning: an uncommitted claim can roll back while its lane is still
 * executing, which lets a second lane claim the same work.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task_type Type to claim. One type per call; the claim index is seeked, not scanned.
 * @param[in] owner Lane identity, as process id, process start time and lane id.
 * @param[in] now Current time; rows are eligible when NEXT_ATTEMPT_AT is at or before it.
 * @param[out] task Claimed task, or NULL when none was eligible. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_claim(wdb_t *wdb, const char *task_type, const char *owner, long long now, cJSON **task);

/**
 * @brief Return a claimed task to the pending state, or retire it if its slot has been taken.
 *
 * @param[in] wdb Tasks database.
 * @param[in] requeue Row to re-queue and the counters to write.
 * @return WDB_MANAGER_TASK_REQUEUED or WDB_MANAGER_TASK_SUPERSEDED, or OS_INVALID on error.
 */
int wdb_manager_task_requeue(wdb_t *wdb, const wdb_manager_task_requeue_t *requeue);

/**
 * @brief Write a terminal outcome and release ownership of the row.
 *
 * Deliberately does not commit; see the note at the head of wdb_manager_task.c.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task_id Row to retire.
 * @param[in] status One of completed, failed or dead_letter.
 * @param[in] last_error May be NULL.
 * @param[in] attempts Value to store; never lower than the row's current value.
 * @param[in] defer_count Value to store.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_set_result(wdb_t *wdb,
                                const char *task_id,
                                const char *status,
                                const char *last_error,
                                int attempts,
                                int defer_count);

/**
 * @brief Fetch one manager task by id.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task_id Row to fetch.
 * @param[out] task The row, or NULL when it does not exist. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_get(wdb_t *wdb, const char *task_id, cJSON **task);

/**
 * @brief Fetch the most recent manager task for one agent and type.
 *
 * Serves authd's outstanding-purge check, which sits on the explicit-id enrollment path.
 *
 * @param[in] wdb Tasks database.
 * @param[in] agent_id Agent to look up.
 * @param[in] task_type Type to look up.
 * @param[out] task The row, or NULL when there is none. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_get_by_agent(wdb_t *wdb, const char *agent_id, const char *task_type, cJSON **task);

/**
 * @brief List the task types that currently have pending work, with the earliest due time of each.
 *
 * One command per poll interval rather than one claim per lane, which would multiply contention
 * on the per-database mutex for no gain.
 *
 * @param[in] wdb Tasks database.
 * @param[out] types Array of {task_type, next_attempt_at}. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_poll(wdb_t *wdb, cJSON **types);

/**
 * @brief Enumerate claimed rows for the ownership sweep, one page at a time.
 *
 * Whether a claimed row may be reclaimed cannot be decided in SQL, because OWNER is a composite
 * the caller parses, so the rows are handed back for the caller to filter.
 *
 * @param[in] wdb Tasks database.
 * @param[in] owner Restrict to one lane, or NULL for every claimed row (the startup form).
 * @param[in] last_task_id Highest task id of the previous page, or NULL to start.
 * @param[in] limit Page size. Must be positive.
 * @param[out] tasks Array of rows with owner, claim time and counters. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_get_claimed(wdb_t *wdb, const char *owner, const char *last_task_id, int limit, cJSON **tasks);

/**
 * @brief List manager tasks of one type, optionally filtered by status, one page at a time.
 *
 * Returns a compact projection rather than whole rows; use wdb_manager_task_get() for a full one.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task_type Type to list.
 * @param[in] status Status to filter by, or NULL for every status.
 * @param[in] last_task_id Highest task id of the previous page, or NULL to start.
 * @param[in] limit Page size. Must be positive.
 * @param[out] tasks Array of {task_id, agent_id, status, create_time, last_error}. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_list(wdb_t *wdb,
                          const char *task_type,
                          const char *status,
                          const char *last_task_id,
                          int limit,
                          cJSON **tasks);

/**
 * @brief Count manager tasks of one type in one status.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task_type Type to count.
 * @param[in] status Status to count.
 * @param[out] count Number of matching rows.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_count(wdb_t *wdb, const char *task_type, const char *status, int *count);

/**
 * @brief List the distinct task types that have pending rows.
 *
 * Half of the orphaned-type reaper: the caller compares this against its handler registry, since
 * wazuh-db has no notion of which task types exist, and fails the ones it does not recognise.
 *
 * @param[in] wdb Tasks database.
 * @param[out] types Array of type names. Caller frees.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_pending_types(wdb_t *wdb, cJSON **types);

/**
 * @brief Move every pending row of one task type to failed.
 *
 * The other half of the reaper. A pending row of an unregistered type is never claimed, is never
 * expired by age, and would otherwise count against the row ceiling forever.
 *
 * @param[in] wdb Tasks database.
 * @param[in] task_type Type to retire.
 * @param[in] last_error Reason to record. May be NULL.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_manager_task_fail_type(wdb_t *wdb, const char *task_type, const char *last_error);

/**
 * @brief Render a MANAGER_TASKS row as JSON, omitting NULL columns.
 *
 * @param[in] stmt Statement positioned on a row selecting the full column list.
 * @return A new cJSON object. Caller frees.
 */
cJSON* wdb_manager_task_row_to_json(sqlite3_stmt *stmt);

/**
 * @brief Wire name of a manager_task_result_t value.
 *
 * @param[in] result Value returned by a queue operation.
 * @return A static string; "unknown" for an unrecognised value.
 */
const char* wdb_manager_task_result_name(int result);

/**
 * @brief Whether a payload stays within the manager task size bound once JSON-escaped.
 *
 * An oversized payload is writable but never claimable, since the claim response carries it back
 * through the same fixed response buffer, so it is refused at creation instead.
 *
 * @param[in] payload Raw payload text.
 * @return true when the payload fits.
 */
bool wdb_manager_task_payload_fits(const char *payload);

/* Manager task sub-command handlers, reached through the task actor's command table.
 *
 * Every one of them takes a JSON parameters object, including those that read nothing from it, so
 * that the dispatch stays uniform: the caller of a parameterless sub-command sends "{}". */
int wdb_parse_manager_task_create(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_claim(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_requeue(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_result(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_get(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_get_by_agent(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_poll(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_get_claimed(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_list(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_count(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_pending_types(wdb_t *wdb, const cJSON *parameters, char *output);
int wdb_parse_manager_task_fail_type(wdb_t *wdb, const cJSON *parameters, char *output);

int wdb_parse_task_create(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the task get_pending request.
 *
 * @param [in] wdb The task struct database.
 * @param parameters JSON with the parameters (agent_id)
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_get_pending(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the task mark_delivered request.
 *
 * @param [in] wdb The task struct database.
 * @param parameters JSON with the parameters (task_id, delivery_time)
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_mark_delivered(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the task cleanup_expired request.
 *
 * @param [in] wdb The task struct database.
 * @param parameters JSON with the parameters (ttl)
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_cleanup_expired(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the task delete_old request.
 *
 * @param [in] wdb The task struct database.
 * @param parameters JSON with the parameters (timestamp)
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_delete_old(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * Create a new generic task in the tasks DB.
 * @param wdb The task struct database
 * @param task_id Deterministic task ID (UUID format)
 * @param agent_id Agent identifier (TEXT format, supports non-numeric IDs)
 * @param task_type Task type (active_response, remote_upgrade, agent_restart, agent_reload)
 * @param payload Complete JSON payload for agent
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_create(wdb_t* wdb, const char *task_id, const char *agent_id, const char *task_type, const char *payload);

/**
 * Get pending tasks for an agent from the tasks DB.
 * @param wdb The task struct database
 * @param agent_id Agent identifier
 * @param max_tasks Maximum number of tasks to return
 * @param tasks_json Output JSON array with pending tasks
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_get_pending(wdb_t* wdb, const char *agent_id, int max_tasks, cJSON **tasks_json);

/**
 * Mark a task as delivered in the tasks DB.
 * @param wdb The task struct database
 * @param task_id Task identifier
 * @param delivery_time Unix timestamp when task was delivered
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_mark_delivered(wdb_t* wdb, const char *task_id, time_t delivery_time);

/**
 * Mark expired tasks in the tasks DB.
 * @param wdb The task struct database
 * @param ttl Time-to-live in seconds
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_cleanup_expired(wdb_t* wdb, int ttl);

/**
 * Delete old expired/delivered tasks from the tasks DB.
 * @param wdb The task struct database
 * @param timestamp Cutoff timestamp (tasks older than this are deleted)
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_delete_old(wdb_t* wdb, time_t timestamp);

// Finalize a statement securely
#define wdb_finalize(x) { if (x) { sqlite3_finalize(x); x = NULL; } }

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

/**
 * @brief Set the synchronous mode of the SQLite database session to FULL.
 *
 * Unlike NORMAL, FULL guarantees that a transaction reported as committed survives a host
 * crash or power loss without waiting for the next WAL checkpoint. Databases whose purpose
 * is durability (tasks.db) must use this mode; see wdb_open_tasks().
 *
 * @param[in] wdb The database structure.
 * @return Returns 0 on success or -1 if an error occurs while setting the synchronous mode.
 */
int wdb_set_synchronous_full(wdb_t * wdb);

/**
 * @brief Set the journal mode of the SQLite database session to WAL.
 *
 * Must be called before any transaction is opened on the session: PRAGMA journal_mode is a
 * no-op inside a transaction. The resulting mode is read back and a warning is logged if the
 * engine refused the change (which it does, for instance, on some network filesystems),
 * because the failure is otherwise silent.
 *
 * @param[in] wdb The database structure.
 * @return Returns 0 on success or -1 if the journal mode could not be set to WAL.
 */
int wdb_set_journal_wal(wdb_t * wdb);

#endif

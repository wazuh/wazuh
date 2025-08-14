/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

wdb_t* __wrap_wdb_open_global() {
    return mock_ptr_type(wdb_t*);
}

int __wrap_wdb_begin2(__attribute__((unused)) wdb_t* aux) {
    return mock();
}

int __wrap_wdb_finalize() {
    return mock();
}

int __wrap_wdb_step(__attribute__((unused)) sqlite3_stmt *stmt) {
    return mock();
}

int __wrap_wdb_stmt_cache(__attribute__((unused)) wdb_t wdb,
                          __attribute__((unused)) int index) {
    return mock();
}

void expect_wdb_stmt_cache_call(int ret) {
    will_return(__wrap_wdb_stmt_cache, ret);
}

cJSON * __wrap_wdb_exec_stmt(__attribute__((unused)) sqlite3_stmt *stmt) {
    return mock_ptr_type(cJSON *);
}

cJSON * __wrap_wdb_exec_stmt_sized(__attribute__((unused)) sqlite3_stmt *stmt,
                                   size_t max_size,
                                   int* status,
                                   bool column_mode) {
    check_expected(max_size);
    check_expected(column_mode);
    *status = mock();
    return mock_ptr_type(cJSON *);
}

int __wrap_wdbc_parse_result(char *result, char **payload) {
    check_expected(result);

    char *ptr = strchr(result, ' ');
    if (ptr) {
        *ptr++ = '\0';
    } else {
        ptr = result;
    }
    if (payload) {
        *payload = ptr;
    }

    return mock();
}

int __wrap_wdbc_query_ex(int *sock, const char *query, char *response, const int len) {
    check_expected(*sock);
    check_expected(query);
    check_expected(len);

    snprintf(response, len, "%s", mock_ptr_type(char*));

    return mock();
}

int __wrap_wdbc_connect_with_attempts(__attribute__((unused)) int max_attempts) {

    if (max_attempts <= 0) {
        fail_msg("Attempts must be greater than 0.");
    }
    return mock();
}

cJSON* __wrap_wdbc_query_parse_json(__attribute__((unused)) int *sock,
                                    __attribute__((unused)) const char *query,
                                    char *response,
                                    __attribute__((unused)) const int len) {
    int option;

    option = mock_type(int);

    switch (option) {
    case -2:
        merror("Unable to connect to socket '%s'", WDB_LOCAL_SOCK);
        break;
    case -1:
        merror("No response from wazuh-db.");
        break;
    case 0:
        break;
    case 1:
        snprintf(response, OS_SIZE_6144, "%s", mock_ptr_type(char*));
        merror("Bad response from wazuh-db: %s", response + 4);
        break;
    }

    return mock_ptr_type(cJSON *);
}

wdbc_result __wrap_wdbc_query_parse(int *sock,
                                    const char *query,
                                    char *response,
                                    const int len,
                                    char** payload) {
    check_expected(sock);
    check_expected(query);
    check_expected(len);

    snprintf(response, len, "%s", mock_ptr_type(char*));

    char* ptr = strchr(response, ' ');
    if (payload) {
        *payload = ptr ? ptr+1 : NULL;
    }

    return mock();
}

cJSON* __wrap_wdb_exec(__attribute__((unused)) sqlite3 *db, const char *sql) {
    check_expected(sql);
    return mock_ptr_type(cJSON*);
}

void __wrap_wdb_leave(__attribute__((unused)) wdb_t *wdb){;}

int __wrap_wdb_sql_exec(__attribute__((unused)) wdb_t *wdb,
                        const char *sql_exec) {
    check_expected(sql_exec);
    return mock();
}

wdb_t* __wrap_wdb_init(__attribute__((unused)) sqlite3* db, const char* id) {
    check_expected(id);
    return mock_ptr_type(wdb_t*);
}

int __wrap_wdb_close(__attribute__((unused)) wdb_t * wdb, __attribute__((unused))bool commit) {
    int free_db = mock_type(int);

    if (free_db) {
        os_free(wdb->db);
    }

    return mock();
}

int __wrap_wdb_create_global(const char *path) {
    check_expected(path);
    return mock();
}

void __wrap_wdb_pool_append(wdb_t * wdb) {
    check_expected(wdb);
}

sqlite3_stmt* __wrap_wdb_init_stmt_in_cache( __attribute__((unused)) wdb_t* wdb, wdb_stmt statement_index){
    check_expected(statement_index);
    return mock_ptr_type(sqlite3_stmt*);
}

int __wrap_wdb_exec_stmt_silent(__attribute__((unused)) sqlite3_stmt* stmt) {
    return mock();
}

int __wrap_wdb_exec_stmt_send(__attribute__((unused)) sqlite3_stmt* stmt, int peer) {
    check_expected(peer);
    return mock();
}

sqlite3_stmt * __wrap_wdb_get_cache_stmt(__attribute__((unused)) wdb_t * wdb, __attribute__((unused)) char const *query) {
    return mock_ptr_type(sqlite3_stmt*);
}

cJSON *__wrap_wdb_get_internal_config() {
    return mock_ptr_type(cJSON *);
}

cJSON *__wrap_wdb_get_config() {
    return mock_ptr_type(cJSON *);
}

int __wrap_wdb_get_global_group_hash(__attribute__((unused))wdb_t * wdb,
                                     os_sha1 hexdigest) {
    check_expected(hexdigest);
    return mock();
}

int __wrap_wdb_commit2(__attribute__((unused))wdb_t * wdb) {
    return mock();
}

void __wrap_wdb_finalize_all_statements(__attribute__((unused))wdb_t * wdb) {
    function_called();
}

int __wrap_wdb_vacuum(__attribute__((unused))sqlite3 * db) {
    return mock();
}

int __wrap_wdb_get_db_state(__attribute__((unused))wdb_t * wdb) {
    return mock();
}

int __wrap_wdb_update_last_vacuum_data(__attribute__((unused))wdb_t* wdb, __attribute__((unused))const char *last_vacuum_time, const char *last_vacuum_value) {
    check_expected(last_vacuum_value);
    return mock();
}

int __wrap_wdb_get_db_free_pages_percentage(__attribute__((unused))wdb_t * wdb) {
    return mock();
}

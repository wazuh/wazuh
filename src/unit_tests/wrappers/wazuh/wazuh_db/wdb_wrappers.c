/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_wdb_fim_clean_old_entries(__attribute__((unused)) wdb_t* socket) {
    return mock();
}

int __wrap_wdb_fim_delete(__attribute__((unused)) wdb_t *wdb,
                          __attribute__((unused)) const char *file) {
    return mock();
}

int __wrap_wdb_fim_update_date_entry(__attribute__((unused)) wdb_t* socket,
                                     __attribute__((unused)) const char *path) {
    return mock();
}

int __wrap_wdb_finalize() {
    return mock();
}

int  __wrap_wdb_step(__attribute__((unused)) sqlite3_stmt *stmt) {
    return mock();
}

int __wrap_wdb_scan_info_fim_checks_control(__attribute__((unused)) wdb_t* socket,
                                            __attribute__((unused)) const char *last_check) {
    return mock();
}

int __wrap_wdb_scan_info_get(__attribute__((unused)) wdb_t *socket,
                             __attribute__((unused)) const char *module,
                             __attribute__((unused)) char *field, long *output) {
    *output = 0;
    return mock();
}

int __wrap_wdb_scan_info_update(__attribute__((unused)) wdb_t *socket,
                                __attribute__((unused)) const char *module,
                                __attribute__((unused)) char *field,
                                __attribute__((unused)) long *output) {
    return mock();
}

int __wrap_wdb_stmt_cache(__attribute__((unused)) wdb_t wdb,
                          __attribute__((unused)) int index) {
    return mock();
}

int __wrap_wdb_syscheck_load(__attribute__((unused)) wdb_t *wdb,
                             __attribute__((unused)) const char *file,
                             char *output,
                             __attribute__((unused)) size_t size) {
    snprintf(output, OS_MAXSTR + 1, "TEST STRING");
    return mock();
}

int __wrap_wdb_syscheck_save(__attribute__((unused)) wdb_t *wdb,
                             __attribute__((unused)) int ftype,
                             __attribute__((unused)) char *checksum,
                             __attribute__((unused)) const char *file) {
    return mock();
}

int __wrap_wdb_syscheck_save2(__attribute__((unused)) wdb_t *wdb,
                              __attribute__((unused)) const char *payload) {
    return mock();
}

cJSON * __wrap_wdb_exec_stmt(__attribute__((unused)) sqlite3_stmt *stmt) {
    return mock_ptr_type(cJSON *);
}

int __wrap_wdbc_parse_result(char *result, char **payload) {
    int retval = mock();

    check_expected(result);

    if(payload){
        *payload = strchr(result, ' ');
    }

    if(*payload) {
        (*payload)++;
    }
    else {
        *payload = result;
    }

    return retval;
}

int __wrap_wdbc_query_ex(int *sock, const char *query, char *response, const int len) {
    check_expected(*sock);
    check_expected(query);
    check_expected(len);

    snprintf(response, len, "%s", mock_ptr_type(char*));

    return mock();
}

int __wrap_wdbi_query_checksum(__attribute__((unused)) wdb_t *wdb,
                               __attribute__((unused)) wdb_component_t component,
                               __attribute__((unused)) const char *command,
                               __attribute__((unused)) const char *payload) {
    return mock();
}

int __wrap_wdbi_query_clear(__attribute__((unused)) wdb_t *wdb,
                            __attribute__((unused)) wdb_component_t component,
                            __attribute__((unused)) const char *payload) {
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

cJSON* __wrap_wdb_exec(__attribute__((unused)) sqlite3 *db, 
                 const char *sql) {
    check_expected(sql);
    return mock_ptr_type(cJSON*);
}

void __wrap_wdb_leave(__attribute__((unused)) wdb_t *wdb){;}

int __wrap_wdb_sql_exec(__attribute__((unused)) wdb_t *wdb,
                        const char *sql_exec) {
    check_expected(sql_exec);
    return mock();
}

cJSON* __wrap_wdb_get_agent_info(int id) {
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

wdb_t* __wrap_wdb_init(__attribute__((unused)) sqlite3* db, const char* id) {
    check_expected(id);
    return mock_ptr_type(wdb_t*);
}

int __wrap_wdb_close(__attribute__((unused)) wdb_t * wdb, __attribute__((unused))bool commit) {
    return mock();
}

int __wrap_wdb_create_global(const char *path) {
    check_expected(path);
    return mock();
}

void __wrap_wdb_pool_append(wdb_t * wdb) {
    check_expected(wdb);
}

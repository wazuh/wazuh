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

wdb_t* __wrap_wdb_open_agent2(int agent_id) {
    check_expected(agent_id);
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

int __wrap_wdb_step(__attribute__((unused)) sqlite3_stmt *stmt) {
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

void expect_wdb_stmt_cache_call(int ret) {
    will_return(__wrap_wdb_stmt_cache, ret);
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

cJSON * __wrap_wdb_exec_stmt_single_column(__attribute__((unused)) sqlite3_stmt *stmt) {
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

int __wrap_wdbi_check_sync_status(__attribute__((unused)) wdb_t *wdb,
                                  wdb_component_t component) {
    check_expected(component);
    return mock();
}

void __wrap_wdbi_update_attempt(__attribute__((unused))wdb_t * wdb,
                                wdb_component_t component,
                                long timestamp,
                                os_sha1 last_agent_checksum,
                                os_sha1 manager_checksum,
                                bool legacy) {
    check_expected(component);
    check_expected(timestamp);
    check_expected(last_agent_checksum);
    check_expected(manager_checksum);
    check_expected(legacy);
}

void __wrap_wdbi_update_completion(__attribute__((unused))wdb_t * wdb,
                                wdb_component_t component,
                                long timestamp,
                                os_sha1 last_agent_checksum,
                                os_sha1 manager_checksum) {
    check_expected(component);
    check_expected(timestamp);
    check_expected(last_agent_checksum);
    check_expected(manager_checksum);
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

int  __wrap_wdb_package_save(__attribute__((unused))wdb_t * wdb,
                             const char* scan_id,
                             const char* scan_time,
                             const char* format,
                             const char* name,
                             const char* priority,
                             const char* section,
                             long size,
                             const char* vendor,
                             const char* install_time,
                             const char* version,
                             const char* architecture,
                             const char* multiarch,
                             const char* source,
                             const char* description,
                             const char* location,
                             const char* checksum,
                             const char* item_id,
                             const bool replace) {
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(format);
    check_expected(name);
    check_expected(priority);
    check_expected(section);
    check_expected(size);
    check_expected(vendor);
    check_expected(install_time);
    check_expected(version);
    check_expected(architecture);
    check_expected(multiarch);
    check_expected(source);
    check_expected(description);
    check_expected(location);
    check_expected(checksum);
    check_expected(item_id);
    check_expected(replace);
    return mock();
}

int __wrap_wdb_hotfix_save(__attribute__((unused))wdb_t * wdb,
                           const char* scan_id,
                           const char* scan_time,
                           const char* hotfix,
                           const char* checksum,
                           const bool replace) {
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(hotfix);
    check_expected(checksum);
    check_expected(replace);
    return mock();
}

int __wrap_wdb_package_update(__attribute__((unused))wdb_t * wdb,
                              const char * scan_id) {
    check_expected(scan_id);
    return mock();
}

int __wrap_wdb_package_delete(__attribute__((unused))wdb_t * wdb,
                              const char * scan_id) {
    check_expected(scan_id);
    return mock();
}

int __wrap_wdb_hotfix_delete(__attribute__((unused))wdb_t * wdb,
                              const char * scan_id) {
    check_expected(scan_id);
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

int __wrap_wdb_sca_find(__attribute__((unused))wdb_t *socket, 
                        __attribute__((unused))int pm_id, char *result_found) {

    return mock();
}

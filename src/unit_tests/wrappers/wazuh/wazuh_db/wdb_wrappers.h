/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_WRAPPERS_H
#define WDB_WRAPPERS_H

#include "wazuh_db/wdb.h"

wdb_t* __wrap_wdb_open_global();

int __wrap_wdb_begin2(wdb_t* aux);

int __wrap_wdb_fim_clean_old_entries(wdb_t* socket);

int __wrap_wdb_fim_delete(wdb_t *wdb, const char *file);

int __wrap_wdb_fim_update_date_entry(wdb_t* socket, const char *path);

int __wrap_wdb_finalize();

int  __wrap_wdb_step(__attribute__((unused)) sqlite3_stmt *stmt);

int __wrap_wdb_scan_info_fim_checks_control(wdb_t* socket, const char *last_check);

int __wrap_wdb_scan_info_get(wdb_t *socket, const char *module, char *field, long *output);

int __wrap_wdb_scan_info_update(wdb_t *socket, const char *module, char *field, long *output);

int __wrap_wdb_stmt_cache(wdb_t wdb, int index);

int __wrap_wdb_syscheck_load(wdb_t *wdb, const char *file, char *output, size_t size);

int __wrap_wdb_syscheck_save(wdb_t *wdb, int ftype, char *checksum, const char *file);

int __wrap_wdb_syscheck_save2(wdb_t *wdb, const char *payload);

cJSON * __wrap_wdb_exec_stmt(__attribute__((unused)) sqlite3_stmt *stmt);

int __wrap_wdbc_parse_result(char *result, char **payload);

int __wrap_wdbc_query_ex(int *sock, const char *query, char *response, const int len);

int __wrap_wdbi_query_checksum(wdb_t *wdb, wdb_component_t component, const char *command, const char *payload);

int __wrap_wdbi_query_clear(wdb_t *wdb, wdb_component_t component, const char *payload);

cJSON* __wrap_wdbc_query_parse_json(int *sock, const char *query, char *response, const int len);

cJSON* __wrap_wdb_exec(sqlite3 *db, const char *sql);

void __wrap_wdb_leave(wdb_t *wdb);

int __wrap_wdb_sql_exec(wdb_t *wdb, const char *sql_exec);

cJSON* __wrap_wdb_get_agent_info(int id);

wdb_t* __wrap_wdb_init(sqlite3* db, const char* id);

int __wrap_wdb_close(wdb_t * wdb, bool commit);

int __wrap_wdb_create_global(const char *path);

void __wrap_wdb_pool_append(wdb_t * wdb);

#endif

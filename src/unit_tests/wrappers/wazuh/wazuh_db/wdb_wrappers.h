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

int __wrap_wdb_begin2(wdb_t* aux);

int __wrap_wdb_fim_clean_old_entries(wdb_t* socket);

int __wrap_wdb_fim_delete(wdb_t *wdb, const char *file);

int __wrap_wdb_fim_update_date_entry(wdb_t* socket, const char *path);

int __wrap_wdb_finalize();

int __wrap_wdb_scan_info_fim_checks_control(wdb_t* socket, const char *last_check);

int __wrap_wdb_scan_info_get(wdb_t *socket, const char *module, char *field, long *output);

int __wrap_wdb_scan_info_update(wdb_t *socket, const char *module, char *field, long *output);

int __wrap_wdb_stmt_cache(wdb_t wdb, int index);

int __wrap_wdb_syscheck_load(wdb_t *wdb, const char *file, char *output, size_t size);

int __wrap_wdb_syscheck_save(wdb_t *wdb, int ftype, char *checksum, const char *file);

int __wrap_wdb_syscheck_save2(wdb_t *wdb, const char *payload);

int __wrap_wdbc_parse_result(char *result, char **payload);

int __wrap_wdbc_query_ex(int *sock, const char *query, char *response, const int len);

int __wrap_wdbi_query_checksum(wdb_t *wdb, wdb_component_t component, const char *command, const char *payload);

int __wrap_wdbi_query_clear(wdb_t *wdb, wdb_component_t component, const char *payload);

cJSON* __wrap_wdbc_query_parse_json(int *sock, const char *query, char *response, const int len);

#endif

/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_METADATA_WRAPPERS_H
#define WDB_METADATA_WRAPPERS_H

#include "../wazuh_db/wdb.h"

int __wrap_wdb_count_tables_with_name(wdb_t * wdb, const char * key, int* counter);

int __wrap_wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output);

int __wrap_wdb_is_older_than_v310(wdb_t *wdb);

#endif

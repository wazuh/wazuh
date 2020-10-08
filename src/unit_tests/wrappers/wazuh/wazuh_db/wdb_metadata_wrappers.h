/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_METADATA_WRAPPERS_H
#define WDB_METADATA_WRAPPERS_H

#include "wazuh_db/wdb.h"

int __wrap_wdb_metadata_table_check(wdb_t * wdb, const char * key);

int __wrap_wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output);

#endif

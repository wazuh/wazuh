/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 1, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_DELTA_EVENT_WRAPPERS_H
#define WDB_DELTA_EVENT_WRAPPERS_H

#include "../wazuh_db/wdb.h"


bool __wrap_wdb_delete_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data);
bool __wrap_wdb_upsert_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data);



#endif /* WDB_DELTA_EVENT_WRAPPERS_H */

/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_GLOBAL_WRAPPERS_H
#define WDB_GLOBAL_WRAPPERS_H

#include "wazuh_db/wdb.h"

int __wrap_wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key,char* group, int date_add);
int __wrap_wdb_global_update_agent_name(wdb_t *wdb, int id, char* name);

#endif

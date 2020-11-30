/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_AGENT_WRAPPERS_H
#define WDB_AGENT_WRAPPERS_H

#include "wazuh_db/wdb.h"

cJSON* __wrap_wdb_get_agent_labels(int id, int *sock);
int __wrap_wdb_find_agent(const char *name, const char *ip, __attribute__((unused)) int *sock);
int* __wrap_wdb_disconnect_agents(int keepalive, const char *sync_status, __attribute__((unused)) int *sock);
cJSON* __wrap_wdb_get_agent_info(int id,  __attribute__((unused)) int *sock);
int* __wrap_wdb_get_agents_by_connection_status(const char* status, __attribute__((unused)) int *sock);

#endif

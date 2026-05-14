/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * February 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_AGENTS_HELPERS_H
#define WDB_AGENTS_HELPERS_H

#include "../wdb.h"

typedef enum agents_db_access {
    WDB_AGENTS_SYS_OSINFO_GET,
} agents_db_access;

/**
 * @brief Gets the sys_osinfo table data of the specified agent's database.
 *
 * @param[in] id The agent ID.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns cJSON object with the sys_osinfo table information. Null in case of error.
 *                 The cJSON object must be freed by the caller.
 */
cJSON* wdb_get_agent_sys_osinfo(int id,
                                int *sock);

#endif

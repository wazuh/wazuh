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

#endif

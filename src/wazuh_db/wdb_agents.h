/*
 * Wazuh DB helper module for agents database
 * Copyright (C) 2015-202, Wazuh Inc.
 * February 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_AGENTS_H
#define WDB_AGENTS_H

#include "wdb.h"

bool wdb_agents_insert_cve(wdb_t *wdb, const cJSON * data);

#endif
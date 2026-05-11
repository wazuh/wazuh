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

#include "wdb.h"

int __wrap_wdb_user_version_get(wdb_t *wdb, int *version);

#endif

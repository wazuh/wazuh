/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_INTEGRITY_WRAPPERS_H
#define WDB_INTEGRITY_WRAPPERS_H

#include "wazuh_db/wdb.h"

void __wrap_wdbi_remove_by_pk(wdb_t *wdb, wdb_component_t component, const char *pk_value);

#endif

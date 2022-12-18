/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "wdb_delta_event_wrappers.h"


bool __wrap_wdb_delete_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data){
    function_called();
    return mock();
}
bool __wrap_wdb_upsert_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data){
    function_called();
    return mock();
}

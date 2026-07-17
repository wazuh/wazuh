/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck.h"

#include "shared.h"
#include "agent_sync_protocol_c_interface.h"

// Persist a syscheck message
void persist_syscheck_msg(const char *id, Operation_t operation, const char *index, const cJSON* _msg, uint64_t version) {
    if (syscheck.enable_synchronization) {
        char* msg = cJSON_PrintUnformatted(_msg);

        mdebug2(FIM_PERSIST, msg);

        // Validation is now done before DBSync insertion in the callbacks
        // This function just persists the already-validated data
        asp_persist_diff(syscheck.sync_handle, id, operation, index, msg, version);

        os_free(msg);
    } else {
        mdebug2("FIM synchronization is disabled");
    }
}

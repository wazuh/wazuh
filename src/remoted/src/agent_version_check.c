/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Lives in its own translation unit so GNU ld's --wrap can intercept its calls to
 * agent_meta_snapshot_str()/wdb_get_agent_info() -- --wrap only redirects references resolved as
 * external at link time; a same-object-file call is bound directly by the compiler and never
 * becomes __wrap_*. This split is what lets test_legacy_task_delivery.c and test_remcom.c mock
 * those two primitives underneath the real function.
 */

#include "agent_metadata_db.h"
#include "wazuhdb_queries_op.h"
#include "version_op.h"

#include <cJSON.h>
#include <stdlib.h>
#include <string.h>

agent_version_check_t agent_meta_check_version(const char* agent_id_str, const char* min_version, char** out_version) {
    agent_meta_t snap = {0};
    char *version = NULL;

    if (agent_meta_snapshot_str(agent_id_str, &snap) == 0 && snap.agent_version && *snap.agent_version) {
        os_strdup(snap.agent_version, version);
    }
    agent_meta_clear(&snap);

    if (!version) {
        cJSON *agent_info = wdb_get_agent_info(atoi(agent_id_str), NULL);

        if (agent_info && agent_info->child) {
            cJSON *version_obj = cJSON_GetObjectItem(agent_info->child, "version");

            if (cJSON_IsString(version_obj) && version_obj->valuestring && *version_obj->valuestring) {
                os_strdup(version_obj->valuestring, version);
            }
        }

        if (agent_info) {
            cJSON_Delete(agent_info);
        }
    }

    if (!version) {
        return AGENT_VERSION_CHECK_UNKNOWN;
    }

    char *version_ptr = strchr(version, 'v');

    if (!version_ptr) {
        if (out_version) { *out_version = version; } else { os_free(version); }
        return AGENT_VERSION_CHECK_UNPARSEABLE;
    }

    bool is_ge = compare_wazuh_versions(version_ptr, min_version, true) >= 0;

    if (out_version) { *out_version = version; } else { os_free(version); }

    return is_ge ? AGENT_VERSION_CHECK_GE_MIN : AGENT_VERSION_CHECK_LT_MIN;
}

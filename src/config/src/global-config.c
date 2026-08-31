/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "global-config.h"
#include "config.h"
#include "string_op.h"

#ifndef CLIENT
#include "mconf-config.h"

/* Reader of the `global` section of the effective YAML document (mconf-config.h). The schema already
 * fixed the types and filled the defaults; only the value rules it cannot express are re-checked. */
int Read_Global_JSON(const struct cJSON *global, void *configp)
{
    _Config *Config = (_Config *)configp;
    const cJSON *item = NULL;

    if (Config == NULL || global == NULL) {
        return (0);
    }

    if (item = cJSON_GetObjectItem(global, "agents_disconnection_time"), item != NULL) {
        long time = w_mconf_json_time(item);

        if (time < 1) {
            w_mconf_json_invalid("agents_disconnection_time", item);
            return (OS_INVALID);
        }
        Config->agents_disconnection_time = time;
    }

    if (item = cJSON_GetObjectItem(global, "agents_disconnection_alert_time"), item != NULL) {
        long time = w_mconf_json_time(item);

        if (time < 0) {
            w_mconf_json_invalid("agents_disconnection_alert_time", item);
            return (OS_INVALID);
        }
        Config->agents_disconnection_alert_time = time;
    }

    return (0);
}
#endif /* CLIENT */

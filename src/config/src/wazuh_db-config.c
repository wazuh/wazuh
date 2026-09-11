/*
 * Wazuh-DB settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "wazuh_db-config.h"
#include "wdb.h"
#include "string_op.h"

void wdb_init_conf() {
    os_calloc(WDB_LAST_BACKUP, sizeof(wdb_backup_settings_node*), wconfig.wdb_backup_settings);

    for (int i = 0; i < WDB_LAST_BACKUP; i++) {
        os_calloc(1, sizeof(wdb_backup_settings_node), wconfig.wdb_backup_settings[i]);
        wconfig.wdb_backup_settings[i]->enabled = true;
        wconfig.wdb_backup_settings[i]->interval = 86400;
        wconfig.wdb_backup_settings[i]->max_files = 3;
    }
}

void wdb_free_conf() {
    for (int i = 0; i < WDB_LAST_BACKUP; i++) {
        os_free(wconfig.wdb_backup_settings[i]);
    }
    os_free(wconfig.wdb_backup_settings);
}

#ifndef CLIENT
#include "mconf-config.h"

/* Reader of the `wdb` section of the effective document (mconf-config.h): fills the global-backup
 * settings of wconfig, which wdb_init_conf() has already set to their defaults. Types and ranges come
 * guaranteed by the schema; the value rules of the XML reader are repeated. */
int Read_WazuhDB_JSON(const struct cJSON *wdb) {
    const cJSON *backup = wdb != NULL ? cJSON_GetObjectItem(wdb, "backup") : NULL;
    const cJSON *global = cJSON_IsObject(backup) ? cJSON_GetObjectItem(backup, "global") : NULL;
    const cJSON *item = NULL;
    wdb_backup_settings_node *settings = NULL;

    if (!cJSON_IsObject(global)) {
        return OS_SUCCESS;
    }

    if (wconfig.wdb_backup_settings == NULL || wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP] == NULL) {
        merror("Wazuh-DB backup settings are not initialized.");
        return OS_INVALID;
    }
    settings = wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP];

    settings->enabled = w_mconf_json_bool(cJSON_GetObjectItem(global, "enabled"), settings->enabled);

    if (item = cJSON_GetObjectItem(global, "interval"), item != NULL) {
        long interval = w_mconf_json_time(item);

        if (interval <= 0) {
            w_mconf_json_invalid("interval", item);
            return OS_INVALID;
        }
        settings->interval = interval;
    }

    if (item = cJSON_GetObjectItem(global, "max_files"), item != NULL) {
        if (!cJSON_IsNumber(item) || item->valuedouble <= 0) {
            w_mconf_json_invalid("max_files", item);
            return OS_INVALID;
        }
        settings->max_files = item->valueint;
    }

    return OS_SUCCESS;
}
#endif /* CLIENT */

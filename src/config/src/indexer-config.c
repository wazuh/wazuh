/*
 * Wazuh Indexer Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * August 31, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include <cJSON.h>

cJSON * indexer_config = NULL;

/* Reader of the `indexer` section of the effective YAML document (etc/wazuh-manager.yml, see
 * mconf-config.h). The schema fills `hosts: []` when the section is absent and every consumer treats a
 * NULL indexer_config as "no indexer configured" (it hands `{}` down), so an empty host list keeps
 * that meaning; otherwise the section is copied as-is (same keys the XML reader used to produce). */
int Read_Indexer_JSON(const cJSON *indexer)
{
    if (indexer_config) {
        cJSON_Delete(indexer_config);
        indexer_config = NULL;
    }

    const cJSON *hosts = indexer ? cJSON_GetObjectItem(indexer, "hosts") : NULL;

    if (!cJSON_IsArray(hosts) || cJSON_GetArraySize(hosts) == 0) {
        return OS_SUCCESS;
    }

    indexer_config = cJSON_Duplicate(indexer, TRUE);

    return OS_SUCCESS;
}

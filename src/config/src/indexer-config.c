/*
 * Wazuh Indexer Configuration
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include <cJSON.h>

cJSON * indexer_config = NULL;

/* Reader of the `indexer` section of the effective document (/etc/wazuh-manager/wazuh-manager.conf, see
 * mconf-config.h). The schema requires the section and a non-empty `hosts`, so a validated document
 * always reaches the copy below; the empty/absent guard only covers a caller handing in no document.
 * Every consumer treats a NULL indexer_config as "no indexer configured" (it hands `{}` down);
 * otherwise the section is copied as-is (same keys the XML reader used to produce). */
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

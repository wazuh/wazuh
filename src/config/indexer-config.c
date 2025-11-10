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

#ifndef CLIENT
#ifndef WIN32

#include "shared.h"
#include "external/cJSON/cJSON.h"
#include "engine_external.h"

cJSON * indexer_config = NULL;

int Read_Indexer(const char* config_file)
{
    if(indexer_config) {
        cJSON_Delete(indexer_config);
        indexer_config = NULL;
    }

    char errBuf[1024] = {0};
    char *indexer_config_str = get_indexer_cnf(config_file, errBuf, sizeof(errBuf));

    if (!indexer_config_str) {
        return OS_INVALID;
    }

    indexer_config = cJSON_Parse(indexer_config_str);
    cJSON_free(indexer_config_str);

    return NULL != indexer_config ? OS_SUCCESS : OS_INVALID;
}

#endif
#endif

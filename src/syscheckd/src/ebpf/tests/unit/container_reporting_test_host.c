/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 * GPLv2.
 */

#include "container_baseline_host_api.h"

extern bool container_reporting_test_persist(const char* id, int operation, int sync_flag);

static syscheck_config config;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool persist(const cJSON* event,
                    const char* id,
                    Operation_t operation,
                    const char* index,
                    uint64_t version,
                    const char* description,
                    bool mark_for_deletion,
                    OSList* failed_list,
                    void* failed_item_data,
                    int sync_flag)
{
    (void)event;
    (void)index;
    (void)version;
    (void)description;
    (void)mark_for_deletion;
    (void)failed_list;
    (void)failed_item_data;
    return container_reporting_test_persist(id, operation, sync_flag);
}

void container_reporting_test_host(int limit)
{
    memset(&config, 0, sizeof(config));
    config.container_file_limit = limit;
    fim_container_host_api_t api = {0};
    api.config = &config;
    api.synced_docs_mutex = &mutex;
    api.validate_and_persist = persist;
    fim_container_baseline_set_host_api(&api);
}

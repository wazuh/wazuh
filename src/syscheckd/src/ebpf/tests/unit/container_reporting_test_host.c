/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 * GPLv2.
 */

#include "container_baseline_host_api.h"

extern bool container_reporting_test_persist(const char* id, int operation, int sync_flag);

static syscheck_config config;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool shutdown_on;
static bool shutdown_process_on(void) { return shutdown_on; }
void container_reporting_test_shutdown(bool value) { shutdown_on = value; }
int container_reporting_test_scan_trylock(void) { return pthread_mutex_trylock(&scan_mutex); }
void container_reporting_test_scan_unlock(void) { pthread_mutex_unlock(&scan_mutex); }

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
    shutdown_on = false;
    api.config = &config;
    api.scan_mutex = &scan_mutex;
    api.shutdown_process_on = shutdown_process_on;
    api.synced_docs_mutex = &mutex;
    api.validate_and_persist = persist;
    fim_container_baseline_set_host_api(&api);
}

void container_reporting_test_frequency(int frequency)
{
    config.container_frequency = frequency;
}

void container_reporting_test_row_limit(int limit)
{
    config.container_file_entry_limit = limit;
}

/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The host functions and configuration container file monitoring needs, and
 * cannot reach by linking.
 *
 * libfimebpf.so is linked INTO wazuh-syscheckd, so everything here is defined
 * in syscheckd_lib, which links this library back. Calling any of it directly
 * leaves the library with undefined symbols that resolve only once the daemon
 * links it -- so nothing else can link it, including its own unit test. The
 * whodata half has always avoided that by taking the host's functions as
 * pointers (fimebpf_initialize); this is the same arrangement for the
 * container half.
 *
 * C ONLY. It pulls in syscheck.h and file.h, neither of which carries
 * extern "C" guards, so a C++ translation unit that included it would take
 * these symbols with C++ linkage and fail to link. The C++ driver reaches
 * them through the shims in container_baseline_fim_bridge.h instead.
 */

#ifndef CONTAINER_BASELINE_HOST_API_H
#define CONTAINER_BASELINE_HOST_API_H

#include "syscheck.h"
#include "file.h"

#include <cJSON.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Everything container file monitoring borrows from the daemon.
 *
 * Registered once, before the baseline walk and the event consumer start.
 * Each member is used only through a NULL check: unregistered means the
 * container path behaves as if nothing were configured, rather than crashing.
 */
typedef struct fim_container_host_api_t
{
    /** The daemon's live configuration. Read, never written, and read through
     *  rather than copied so a configuration reload is picked up. */
    const syscheck_config* config;

    /** The lock guarding the daemon's synced-document counters. The container
     *  counters deliberately share it, so the two populations cannot interleave
     *  an update -- which means it has to be the daemon's own lock, not one of
     *  this library's. NULL leaves the container counters unguarded. */
    pthread_mutex_t* synced_docs_mutex;

    /** FIM's files-per-second budget (check_max_fps). Its token bucket is
     *  process-global, so the container walk shares one budget with the host
     *  walk. NULL leaves the walk unthrottled. */
    void (*rate_limit)(void);

    /** Builds the attribute object of a stateless event. Container rows carry
     *  no fim_file_data, so the container path always uses its JSON-only mode
     *  (data == NULL). */
    cJSON* (*attributes_json)(const cJSON* dbsync_event,
                              const fim_file_data* data,
                              const directory_t* configuration);

    /** Fills changed_attributes/old_attributes from a DBSync row's previous
     *  state, so a container alert reports changed_fields like a host one. */
    void (*calculate_dbsync_difference)(const directory_t* configuration,
                                        const cJSON* old_data,
                                        cJSON* changed_attributes,
                                        cJSON* old_attributes);

    /** Sends a stateless event to the agent queue. */
    void (*send_event)(const cJSON* msg);

    /** Sends a message up to the manager through the agent's log channel. Used
     *  for the saturation notice, following the only pattern the agent has for
     *  telling a manager it is full. NULL means the notice is not sent. */
    int (*send_log)(const char* msg);

    /** Validates a stateful document against its index schema and persists it. */
    bool (*validate_and_persist)(const cJSON* stateful_event,
                                 const char* id,
                                 Operation_t operation,
                                 const char* index,
                                 uint64_t document_version,
                                 const char* item_description,
                                 bool mark_for_deletion,
                                 OSList* failed_list,
                                 void* failed_item_data,
                                 int sync_flag);
} fim_container_host_api_t;

/**
 * @brief Hand container file monitoring the host API.
 *
 * Copied, so the caller need not keep the struct alive -- but `config` is held
 * as a pointer on purpose. Call before fim_container_events_start() and
 * fim_run_container_baseline(). Passing NULL clears it.
 */
void fim_container_baseline_set_host_api(const fim_container_host_api_t* api);

#endif /* CONTAINER_BASELINE_HOST_API_H */

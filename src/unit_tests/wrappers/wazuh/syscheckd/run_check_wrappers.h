/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef RUN_CHECK_WRAPPERS_H
#define RUN_CHECK_WRAPPERS_H

#include "../../../../syscheckd/include/syscheck.h"

int __wrap_send_log_msg(const char * msg);

void __wrap_send_syscheck_msg(char *msg);

void __wrap_persist_syscheck_msg(const char *id,
                                 Operation_t operation,
                                 const char *index,
                                 const cJSON *msg,
                                 uint64_t version);

bool __wrap_validate_and_persist_fim_event(
    const cJSON* stateful_event,
    const char* id,
    Operation_t operation,
    const char* index,
    uint64_t document_version,
    const char* item_description,
    bool mark_for_deletion,
    OSList* failed_list,
    void* failed_item_data
);

void __wrap_cleanup_failed_fim_files(OSList* failed_paths);

void __wrap_cleanup_failed_registry_keys(OSList* failed_keys);

void __wrap_cleanup_failed_registry_values(OSList* failed_values);

void __wrap_fim_sync_check_eps();

// Send a state synchronization message
void __wrap_fim_send_sync_state(const char* location, const char* msg);

#endif

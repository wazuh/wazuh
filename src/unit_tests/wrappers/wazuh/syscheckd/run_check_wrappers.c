/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "run_check_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <cJSON.h>
#include "../shared/debug_op_wrappers.h"
#include "../shared_modules/agent_sync_protocol_wrappers.h"

int __wrap_send_log_msg(const char * msg) {
    check_expected(msg);
    return mock();
}

void __wrap_send_syscheck_msg(__attribute__((unused)) char *msg) {
    function_called();
    return;
}

void __wrap_persist_syscheck_msg(__attribute__((unused))const char *id,
                                 __attribute__((unused))Operation_t operation,
                                 __attribute__((unused))const char *index,
                                 __attribute__((unused))const cJSON *msg,
                                 __attribute__((unused))uint64_t version) {
    function_called();
    return;
}

// Wrapper for validate_and_persist_fim_event - the new function from refactor
bool __wrap_validate_and_persist_fim_event(
    __attribute__((unused)) const cJSON* stateful_event,
    __attribute__((unused)) const char* id,
    __attribute__((unused)) Operation_t operation,
    __attribute__((unused)) const char* index,
    __attribute__((unused)) uint64_t document_version,
    __attribute__((unused)) const char* item_description,
    __attribute__((unused)) bool mark_for_deletion,
    __attribute__((unused)) OSList* failed_list,
    __attribute__((unused)) void* failed_item_data,
    __attribute__((unused)) int sync_flag
) {
    // Tests can override this return value with will_return if needed
    // to simulate validation failures
    return mock_type(bool);
}

// Wrappers for cleanup functions - just no-ops to allow code to execute
void __wrap_cleanup_failed_fim_files(__attribute__((unused)) OSList* failed_paths) {
    // No-op: Let the calling code handle the logic
    return;
}

void __wrap_cleanup_failed_registry_keys(__attribute__((unused)) OSList* failed_keys) {
    // No-op: Let the calling code handle the logic
    return;
}

void __wrap_cleanup_failed_registry_values(__attribute__((unused)) OSList* failed_values) {
    // No-op: Let the calling code handle the logic
    return;
}

void __wrap_fim_sync_check_eps() {
    function_called();
}

// Send a state synchronization message
void __wrap_fim_send_sync_state(const char* location, const char* msg) {
    check_expected(location);
    check_expected(msg);
}

void expect_fim_send_sync_state_call(const char* location, const char* msg) {
    expect_value(__wrap_fim_send_sync_state, location, location);
    expect_value(__wrap_fim_send_sync_state, msg, msg);
}

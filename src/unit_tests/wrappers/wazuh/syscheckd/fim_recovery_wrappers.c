/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "fim_recovery_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_fim_recovery_persist_table_and_resync(__attribute__((unused)) char* table_name,
                                                   __attribute__((unused)) uint32_t sync_response_timeout,
                                                   __attribute__((unused)) long sync_max_eps,
                                                   __attribute__((unused)) AgentSyncProtocolHandle* handle,
                                                   __attribute__((unused)) void* test_callback) {
    function_called();
}

bool __wrap_fim_recovery_check_if_full_sync_required(__attribute__((unused)) char* table_name,
                                                      __attribute__((unused)) uint32_t sync_response_timeout,
                                                      __attribute__((unused)) long sync_max_eps,
                                                      __attribute__((unused)) AgentSyncProtocolHandle* handle) {
    function_called();
    return mock_type(bool);
}

bool __wrap_fim_recovery_integrity_interval_has_elapsed(__attribute__((unused)) char* table_name,
                                                         __attribute__((unused)) int64_t integrity_interval) {
    function_called();
    return mock_type(bool);
}

void __wrap_fim_db_set_first_scan_has_been_synched(void) {
    function_called();
}

bool __wrap_fim_db_check_if_first_scan_has_been_synched(void) {
    function_called();
    return mock_type(bool);
}

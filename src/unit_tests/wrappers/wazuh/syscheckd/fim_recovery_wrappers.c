/* Copyright (C) Wazuh Inc.
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

bool __wrap_fim_recovery_persist_table_and_resync(__attribute__((unused)) char* table_name,
                                                   __attribute__((unused)) AgentSyncProtocolHandle* handle,
                                                   __attribute__((unused)) const OSList* directories_list,
                                                   __attribute__((unused)) const char* retry_note) {
    function_called();
    return mock_type(bool);
}

IntegrityCheckResult_t __wrap_fim_recovery_check_if_full_sync_required(__attribute__((unused)) char* table_name,
                                                                        __attribute__((unused)) AgentSyncProtocolHandle* handle) {
    function_called();
    return *mock_ptr_type(IntegrityCheckResult_t*);
}

bool __wrap_fim_recovery_integrity_interval_has_elapsed(__attribute__((unused)) char* table_name,
                                                         __attribute__((unused)) int64_t integrity_interval) {
    function_called();
    return mock_type(bool);
}

static bool s_recover_first_table = false;

void __wrap_fim_recovery_run_integrity_checks_recover_first_table(bool enable) {
    s_recover_first_table = enable;
}

void __wrap_fim_recovery_run_integrity_checks(__attribute__((unused)) AgentSyncProtocolHandle* handle,
                                              __attribute__((unused)) char** table_names,
                                              int table_count,
                                              __attribute__((unused)) const OSList* directories_list,
                                              __attribute__((unused)) int64_t integrity_interval,
                                              bool* recovered) {
    function_called();

    if (s_recover_first_table && recovered && table_count > 0) {
        recovered[0] = true;
    }
}

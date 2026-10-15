/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef FIM_RECOVERY_WRAPPERS_H
#define FIM_RECOVERY_WRAPPERS_H

#include <stdbool.h>
#include <stdint.h>

#include "agent_sync_protocol_c_interface_types.h"

// Forward declaration for OSList
typedef struct _OSList OSList;

/**
 * @brief Wrapper for fim_recovery_persist_table_and_resync
 */
bool __wrap_fim_recovery_persist_table_and_resync(char* table_name,
                                                   AgentSyncProtocolHandle* handle,
                                                   const OSList* directories_list,
                                                   const char* retry_note);

/**
 * @brief Wrapper for fim_recovery_check_if_full_sync_required
 */
IntegrityCheckResult_t __wrap_fim_recovery_check_if_full_sync_required(char* table_name,
                                                                        AgentSyncProtocolHandle* handle);

/**
 * @brief Wrapper for fim_recovery_integrity_interval_has_elapsed
 */
bool __wrap_fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval);

/**
 * @brief Wrapper for fim_recovery_run_integrity_checks
 */
void __wrap_fim_recovery_run_integrity_checks(AgentSyncProtocolHandle* handle,
                                              char** table_names,
                                              int table_count,
                                              const OSList* directories_list,
                                              int64_t integrity_interval);

#endif

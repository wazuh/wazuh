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

// Forward declaration for AgentSyncProtocolHandle
typedef struct AgentSyncProtocolHandle AgentSyncProtocolHandle;

/**
 * @brief Wrapper for fim_recovery_persist_table_and_resync
 */
void __wrap_fim_recovery_persist_table_and_resync(char* table_name,
                                                   AgentSyncProtocolHandle* handle,
                                                   void* test_callback,
                                                   void* log_callback);

/**
 * @brief Wrapper for fim_recovery_check_if_full_sync_required
 */
bool __wrap_fim_recovery_check_if_full_sync_required(char* table_name,
                                                      AgentSyncProtocolHandle* handle,
                                                      void* log_callback);

/**
 * @brief Wrapper for fim_recovery_integrity_interval_has_elapsed
 */
bool __wrap_fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval);

#endif

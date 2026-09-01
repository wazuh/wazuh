/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ASP_WRAPPERS_H
#define ASP_WRAPPERS_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include "agent_sync_protocol_c_interface.h"

AgentSyncProtocolHandle* __wrap_asp_create(const char* module, const char* db_path, asp_logger_t logger,
                                            uint64_t flush_batch_size, uint64_t flush_interval_ms);

void __wrap_asp_persist_diff(AgentSyncProtocolHandle* handle,
                             const char* id,
                             int operation,
                             const char* index,
                             const char* data,
                             uint64_t version);

SyncModuleResult_t __wrap_asp_sync_module(AgentSyncProtocolHandle* handle,
                                          int mode);

/**
 * @brief Wrapper for asp_get_agent_id. Scripted with will_return(): 0 means "the provider has
 *        published nothing", which callers must read as unknown rather than as a new identity.
 */
long __wrap_asp_get_agent_id(void);

/// @brief Switches __wrap_asp_sync_module() between its default behavior (a single
/// will_return(bool) populates only SyncModuleResult_t.success, everything else zeroed) and full
/// mode (a single will_return(SyncModuleResult_t*) supplies the whole struct). Off by default so
/// existing will_return(__wrap_asp_sync_module, <bool>) call sites keep working unchanged; tests
/// that need to drive classification flags (e.g. local_transport_unavailable) call this with true.
void __wrap_asp_sync_module_use_full_result(bool enable);

bool __wrap_asp_requires_full_sync(AgentSyncProtocolHandle* handle,
                                   const char* index,
                                   const char* checksum);

bool __wrap_asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data, size_t length);

bool __wrap_asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                                  const char** indices,
                                  size_t indices_count);

void __wrap_asp_delete_database(AgentSyncProtocolHandle* handle);

#endif

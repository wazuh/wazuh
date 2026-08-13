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

AgentSyncProtocolHandle* __wrap_asp_create(const char* module, const char* db_path, asp_logger_t logger);

void __wrap_asp_persist_diff(AgentSyncProtocolHandle* handle,
                             const char* id,
                             int operation,
                             const char* index,
                             const char* data,
                             uint64_t version);

SyncModuleResult_t __wrap_asp_sync_module(AgentSyncProtocolHandle* handle,
                                          int mode);

bool __wrap_asp_requires_full_sync(AgentSyncProtocolHandle* handle,
                                   const char* index,
                                   const char* checksum);

bool __wrap_asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data, size_t length);

bool __wrap_asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                                  const char** indices,
                                  size_t indices_count);

void __wrap_asp_delete_database(AgentSyncProtocolHandle* handle);

#endif

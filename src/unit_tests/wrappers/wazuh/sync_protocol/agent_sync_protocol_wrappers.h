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

AgentSyncProtocolHandle* __wrap_asp_create(const char* module, const MQ_Functions* mq_funcs);

void __wrap_asp_destroy(AgentSyncProtocolHandle* handle);

void __wrap_asp_persist_diff(AgentSyncProtocolHandle* handle,
                             const char* id,
                             int operation,
                             const char* index,
                             const char* data);

bool __wrap_asp_sync_module(AgentSyncProtocolHandle* handle,
                            int mode,
                            unsigned int sync_timeout,
                            unsigned int retries,
                            size_t max_eps);

int __wrap_asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data);

#endif

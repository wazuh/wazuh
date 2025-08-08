/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "agent_sync_protocol_wrappers.h"

AgentSyncProtocolHandle* __wrap_asp_create(const char* module, const MQ_Functions* mq_funcs) {
    check_expected_ptr(module);
    (void)mq_funcs;
    return mock_ptr_type(AgentSyncProtocolHandle*);
}

void __wrap_asp_destroy(AgentSyncProtocolHandle* handle) {
    check_expected_ptr(handle);
}

void __wrap_asp_persist_diff(AgentSyncProtocolHandle* handle,
                             const char* id,
                             int operation,
                             const char* index,
                             const char* data) {
    check_expected_ptr(handle);
    check_expected_ptr(id);
    check_expected(operation);
    check_expected_ptr(index);
    check_expected_ptr(data);
}

bool __wrap_asp_sync_module(AgentSyncProtocolHandle* handle,
                            int mode,
                            unsigned int sync_timeout,
                            unsigned int retries,
                            size_t max_eps) {
    check_expected_ptr(handle);
    check_expected(mode);
    check_expected(sync_timeout);
    check_expected(retries);
    check_expected(max_eps);
    return mock_type(bool);
}

int __wrap_asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data) {
    check_expected_ptr(handle);
    check_expected_ptr(data);
    return mock_type(int);
}
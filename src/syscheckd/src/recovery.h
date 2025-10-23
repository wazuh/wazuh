/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 22 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
// We avoid the definition __declspec(dllimport) as a workaround for the MinGW bug
// for delayed loaded DLLs in 32bits (https://www.sourceware.org/bugzilla/show_bug.cgi?id=14339)
#define EXPORTED
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "agent_sync_protocol.hpp"

#ifdef __cplusplus
extern "C"
{
#endif

EXPORTED void recover_module_data(char* table_name, AgentSyncProtocolHandle* handle, uint32_t sync_response_timeout, long sync_max_eps);

#ifdef __cplusplus
}
#endif // _cplusplus

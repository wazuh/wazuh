/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The library's log sink (I56). loggerHelper.h's GLOBAL_LOG_FUNCTION has hidden visibility: every DSO defines its own,
// and this is the one of libindexer_client.so (and of the test build's static library). The process hands its log
// function to setLogFunction(), the same one it gave the v1 connector library (removed in 5.x).

#include "indexer_client/runtime.hpp"
#include "loggerHelper.h"
#include "runtime/runtimeInternal.hpp"

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

namespace indexer_client
{
    void setLogFunction(LogFunction logFunction)
    {
        // Runtime threads read the sink without synchronization (loggerHelper.h): it may only change while no runtime
        // thread exists, checked under the lock that serializes start() and shutdown().
        if (!detail::withNoRuntime([&logFunction]() { Log::GLOBAL_LOG_FUNCTION = std::move(logFunction); }))
        {
            detail::countUsageError();
        }
    }
} // namespace indexer_client

/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testHooks.hpp"

#include <mutex>
#include <utility>

namespace
{
    std::mutex g_hookMutex;
    wazuh::uds_http::test_hooks::InterimWriteHook g_interimWriteHook;
} // namespace

namespace wazuh::uds_http::test_hooks
{
    void setInterimWriteHook(InterimWriteHook hook)
    {
        std::lock_guard lock {g_hookMutex};
        g_interimWriteHook = std::move(hook);
    }
} // namespace wazuh::uds_http::test_hooks

namespace wazuh::uds_http::detail
{
    // Strong definition: replaces the library's weak production default (always "write at once") in
    // this binary only. The signature must match the one in src/asioUdsHttpServer.cpp; if it drifted,
    // the weak default would win and the overlap tests would fail waiting for a held write.
    bool interceptInterimWrite(const std::function<void()>& startWrite)
    {
        test_hooks::InterimWriteHook hook;
        {
            std::lock_guard lock {g_hookMutex};
            hook = g_interimWriteHook;
        }
        if (!hook)
        {
            return false;
        }
        hook(startWrite);
        return true;
    }
} // namespace wazuh::uds_http::detail

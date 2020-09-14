/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * August 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "rsync_implementation.h"
#include "rsync_exception.h"

using namespace RSync;

void RSyncImplementation::release()
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    m_remoteSyncContexts.clear();
}

bool RSyncImplementation::releaseContext(const RSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    return 1 == m_remoteSyncContexts.erase(handle);
}

RSYNC_HANDLE RSyncImplementation::create()
{
    const auto spRSyncContext
    {
        std::make_shared<RSyncContext>()
    };
    const RSYNC_HANDLE handle{ spRSyncContext.get() };
    std::lock_guard<std::mutex> lock{m_mutex};
    m_remoteSyncContexts[handle] = spRSyncContext;
    return handle;
}

std::shared_ptr<RSyncImplementation::RSyncContext> RSyncImplementation::remoteSyncContext(const RSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{m_mutex};
    const auto it{ m_remoteSyncContexts.find(handle) };
    if (it == m_remoteSyncContexts.end())
    {
        throw rsync_error { INVALID_HANDLE };
    }
    return it->second;
}

void RSyncImplementation::push(const RSYNC_HANDLE handle, const std::vector<unsigned char>& data)
{
    const auto spRSyncContext
    {
        remoteSyncContext(handle)
    };
    //spRSyncContext->m_msgDispatcher.push(data);
}

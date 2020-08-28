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

void RSyncImplementation::releaseContext(const RSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    if (0 == m_remoteSyncContexts.erase(handle))
    {
        throw rsync_error{ ELEMENT_NOT_EXIST};
    }
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




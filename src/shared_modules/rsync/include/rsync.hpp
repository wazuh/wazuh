/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSYNC_HPP_
#define _RSYNC_HPP_

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <functional>
#include "json.hpp"

using SyncCallbackData = const std::function<void(const std::string&)>&;

class EXPORTED RemoteSync 
{
public:
    RemoteSync();
    RemoteSync(RSYNC_HANDLE handle);
    // LCOV_EXCL_START
    virtual ~RemoteSync();
    // LCOV_EXCL_STOP
    static void teardown();

    virtual void startSync(const DBSYNC_HANDLE   dbsyncHandle,
                           const nlohmann::json& startConfiguration,
                           SyncCallbackData&     callbackData);

    virtual void registerSyncID(const std::string&    messageHeaderID, 
                                const DBSYNC_HANDLE   dbsyncHandle,
                                const nlohmann::json& syncConfiguration,
                                SyncCallbackData&     callbackData);

    virtual void pushMessage(const std::vector<uint8_t>& payload);

    RSYNC_HANDLE getHandle() { return m_handle;}

private:
    RSYNC_HANDLE m_handle;
    bool m_shouldBeRemove;

};


#endif // _RSYNC_HPP_
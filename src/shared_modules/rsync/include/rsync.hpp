/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "commonDefs.h"

using SyncCallbackData = const std::function<void(const std::string&)>;

class EXPORTED RemoteSync 
{
public:
    /**
    * @brief Initializes the shared library.
    *
    * @param logFunction pointer to log function to be used by the rsync.
    */
    static void initialize(std::function<void(const std::string&)> logFunction);

    /**
     * @brief Remote sync initializes the instance. 
     */
    RemoteSync();

    /**
     * @brief RSync Constructor.
     *
     * @param handle     handle to point another rsync instance.
     *
     */
    RemoteSync(RSYNC_HANDLE handle);
    // LCOV_EXCL_START
    virtual ~RemoteSync();
    // LCOV_EXCL_STOP

    /**
     * @brief Turns off the services provided by the shared library.
     */
    static void teardown();

    /**
     * @brief Initializes the \p handle instance.
     * @param dbsyncHandle       DBSync handle to synchronize databases.
     * @param startConfiguration Statement used as a synchronization start.
     * @param callbackData       This callback is used to send sync information.
     * 
     */
    virtual void startSync(const DBSYNC_HANDLE   dbsyncHandle,
                           const nlohmann::json& startConfiguration,
                           SyncCallbackData      callbackData);

    /**
     * @brief Establishes a message-id to be processed in the agent-manager sync.
     *
     * @param messageHeaderID    Message ID associated to procees messages between
     *                           agent and manager.
     * @param dbsyncHandle       DBSync handle to synchronize databases.
     * @param syncConfiguration  Statement used as a configuration.
     * @param callbackData       This callback is used to send sync information.
     *
     */
    virtual void registerSyncID(const std::string&    messageHeaderID, 
                                const DBSYNC_HANDLE   dbsyncHandle,
                                const nlohmann::json& syncConfiguration,
                                SyncCallbackData      callbackData);
    /**
     * @brief Pushes the \p payload message within a queue to process it in an async 
     *  dispatch queue.
     *
     * @param payload Message to be queued and processed.
     *
     */
    virtual void pushMessage(const std::vector<uint8_t>& payload);
    /**
     * @brief Get current rsync handle in the instance.
     *
     * @return RSYNC_HANDLE to be used in all internal calls.
     */
    RSYNC_HANDLE handle() { return m_handle; }

private:
    RSYNC_HANDLE m_handle;
    bool m_shouldBeRemoved;

};


#endif // _RSYNC_HPP_
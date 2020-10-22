/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * August 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <string>
#include "rsync.h"
#include "rsync.hpp"
#include "rsync_exception.h"
#include "dbsyncWrapper.h"
#include "rsyncImplementation.h"


#ifdef __cplusplus
extern "C" {
#endif

using namespace RSync;

static log_fnc_t gs_logFunction{ nullptr };

static void log_message(const std::string& msg)
{
    if (!msg.empty())
    {
        if (gs_logFunction)
        {
            gs_logFunction(msg.c_str());
        }
    }
}

EXPORTED void rsync_initialize(log_fnc_t log_function)
{
    if (!gs_logFunction)
    {
        gs_logFunction = log_function;
    }
}

EXPORTED void rsync_teardown(void)
{
    RSyncImplementation::instance().release();
}

EXPORTED RSYNC_HANDLE rsync_create()
{
    RSYNC_HANDLE retVal{ nullptr };
    std::string errorMessage;
    try
    {
        retVal = RSyncImplementation::instance().create();
    }
    // LCOV_EXCL_START
    catch(...)
    {
        errorMessage += "Unrecognized error.";
    }
    // LCOV_EXCL_STOP
    
    log_message(errorMessage);
    return retVal;
}

EXPORTED int rsync_start_sync(const RSYNC_HANDLE handle,
                              const DBSYNC_HANDLE dbsync_handle,
                              const cJSON* start_configuration,
                              sync_callback_data_t callback_data)
{
    auto retVal { -1 };
    std::string errorMessage;
    if (!handle || !dbsync_handle || !start_configuration || !callback_data.callback)
    {
        errorMessage += "Invalid parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](const std::string& payload)
                {
                    callback_data.callback(payload.c_str(), payload.size(), callback_data.user_data);
                }
            };
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(start_configuration)};
            RSyncImplementation::instance().startRSync(handle, std::make_shared<DBSyncWrapper>(dbsync_handle), nlohmann::json::parse(spJsonBytes.get()), callbackWrapper);
            retVal = 0;
        }
        // LCOV_EXCL_START
        catch(...)
        {
            errorMessage += "Unrecognized error.";
        }
        // LCOV_EXCL_STOP
    }
    log_message(errorMessage);
    return retVal;
}

EXPORTED int rsync_register_sync_id(const RSYNC_HANDLE handle, 
                                    const char* message_header_id, 
                                    const DBSYNC_HANDLE dbsync_handle,
                                    const cJSON* sync_configuration,
                                    sync_callback_data_t callback_data)
{
    int retVal{ -1 };
    std::string errorMessage;
    if (!message_header_id || !dbsync_handle || !sync_configuration || !callback_data.callback)
    {
        errorMessage += "Invalid Parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](const std::string& payload)
                {
                    callback_data.callback(payload.c_str(), payload.size(), callback_data.user_data);
                }
            };
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_Print(sync_configuration)};
            RSyncImplementation::instance().registerSyncId(handle, message_header_id, std::make_shared<DBSyncWrapper>(dbsync_handle), nlohmann::json::parse(spJsonBytes.get()), callbackWrapper);
            retVal = 0;
        }
        // LCOV_EXCL_START
        catch(...)
        {
            errorMessage += "Unrecognized error.";
        }
        // LCOV_EXCL_STOP
    }
    
    log_message(errorMessage);
    return retVal; 
}

EXPORTED int rsync_push_message(const RSYNC_HANDLE handle,
                                const void* payload,
                                const size_t size)
{
    auto retVal { -1 };
    std::string errorMessage;
    if (!handle || !payload || !size)
    {
        errorMessage += "Invalid Parameters.";
    }
    else
    {
        try
        {
            const auto first{reinterpret_cast<const unsigned char*>(payload)};
            const auto last{first + size};
            const std::vector<unsigned char> data{first, last};
            RSyncImplementation::instance().push(handle, data);
            retVal = 0;
        }
        // LCOV_EXCL_START
        catch(...)
        {
            errorMessage += "Unrecognized error.";
        }
        // LCOV_EXCL_STOP
    }
    log_message(errorMessage);
    return retVal;
}

EXPORTED int rsync_close(const RSYNC_HANDLE handle)
{
    std::string message;
    auto retVal { 0 };
    
    try
    {
        RSyncImplementation::instance().releaseContext(handle);
    }
    // LCOV_EXCL_START
    catch (...)
    {
        message += "RSYNC invalid context handle.";
        retVal = -1;
    }
    // LCOV_EXCL_STOP

    log_message(message);
    return retVal;
}

#ifdef __cplusplus
}
#endif

void RemoteSync::teardown()
{
    RSyncImplementation::instance().release();
}

RemoteSync::RemoteSync()
: m_shouldBeRemoved{ true }
{
    m_handle = RSyncImplementation::instance().create();
}

RemoteSync::RemoteSync(RSYNC_HANDLE handle)
: m_handle { handle }
, m_shouldBeRemoved{ false }
{ }

RemoteSync::~RemoteSync()
{
    if (m_shouldBeRemoved)
    {
        RSyncImplementation::instance().releaseContext(m_handle);
    }
}

void RemoteSync::startSync(const DBSYNC_HANDLE   dbsyncHandle,
                           const nlohmann::json& startConfiguration,
                           SyncCallbackData      callbackData)
{
    const auto callbackWrapper
    {
        [callbackData](const std::string& payload)
        {
            callbackData(payload);
        }
    };
    RSyncImplementation::instance().startRSync(m_handle, std::make_shared<DBSyncWrapper>(dbsyncHandle), startConfiguration, callbackWrapper);
            
}

void RemoteSync::registerSyncID(const std::string&    messageHeaderID, 
                                const DBSYNC_HANDLE   dbsyncHandle,
                                const nlohmann::json& syncConfiguration,
                                SyncCallbackData      callbackData)
{
    const auto callbackWrapper
    {
        [callbackData](const std::string& payload)
        {
            callbackData(payload);
        }
    };
    RSyncImplementation::instance().registerSyncId(m_handle, messageHeaderID, std::make_shared<DBSyncWrapper>(dbsyncHandle), syncConfiguration, callbackWrapper);       
}

void RemoteSync::pushMessage(const std::vector<uint8_t>& payload)
{
    RSyncImplementation::instance().push(m_handle, payload);       
}


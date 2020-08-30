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
#include "rsync_exception.h"
#include "rsync_implementation.h"

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

EXPORTED int rsync_start_sync(const RSYNC_HANDLE /*handle*/)
{
    return 0;    
}

EXPORTED int rsync_register_sync_id(const RSYNC_HANDLE /*handle*/, 
                                    const char* /*message_header_id*/, 
                                    const DBSYNC_HANDLE /*dbsync_handle*/,
                                    const cJSON* /*sync_configuration*/,
                                    sync_callback_data_t /*callback_data*/)
{
    return 0;    
}

EXPORTED int rsync_push_message(const RSYNC_HANDLE /*handle*/,
                                const char* /*payload*/)
{
    return 0;    
}

EXPORTED int rsync_close(const RSYNC_HANDLE handle)
{
    std::string message;
    auto retVal { 0 };
    
    if (!RSyncImplementation::instance().releaseContext(handle))
    {
        message += "RSYNC invalid context handle.";
        retVal = -1;
    }

    log_message(message);
    return retVal;
}

#ifdef __cplusplus
}
#endif
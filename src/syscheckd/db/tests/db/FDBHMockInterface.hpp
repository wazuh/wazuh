/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDB.hpp"
#include "FDBHMockClass.hpp"

#ifndef _FIMDB_HELPERS_MOCK_INTERFACE_
#define _FIMDB_HELPERS_MOCK_INTERFACE_

namespace FIMDBHelpersUTInterface
{

#ifndef WIN32

    void initDB(unsigned int sync_interval, unsigned int file_limit,
                fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDB(sync_interval, file_limit, sync_callback, logCallback, handler_DBSync, handler_RSync);
    }
#else

    void initDB(unsigned int sync_interval, unsigned int file_limit, unsigned int registry_limit,
                fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDB(sync_interval, file_limit, registry_limit, sync_callback, logCallback, handler_DBSync,
                                               handler_RSync);
    }
#endif


    void removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        FIMDBHelpersMock::getInstance().removeFromDB(tableName, filter);
    }

    void getCount(const std::string& tableName, int& count)
    {
        FIMDBHelpersMock::getInstance().getCount(tableName, count);
    }

    void updateItem(const std::string& tableName, const nlohmann::json& item)
    {

        FIMDBHelpersMock::getInstance().updateItem(tableName, item);
    }

    void getDBItem(nlohmann::json& item, const nlohmann::json& query)
    {
        FIMDBHelpersMock::getInstance().executeQuery(item, query);
    }
}

#endif

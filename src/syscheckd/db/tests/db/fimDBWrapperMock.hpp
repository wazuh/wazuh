/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 24, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_WRAPPER_MOCK
#define _FIMDB_WRAPPER_MOCK

namespace FIMDBWrapperMock
{
    template<typename T>
#ifndef WIN32

    void initDB(unsigned int sync_interval, unsigned int file_limit,
                fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        T::initDB(sync_interval, file_limit, sync_callback, logCallback, handler_DBSync, handler_RSync);
    }
#else

    void initDB(unsigned int sync_interval, unsigned int file_limit, unsigned int registry_limit,
                fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        T::initDB(sync_interval, file_limit, registry_limit, sync_callback, logCallback, handler_DBSync,
                                        handler_RSync);
    }
#endif

    template<typename T>
    void removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        T::removeFromDB(tableName, filter);
    }

    template<typename T>
    void getCount(const std::string& tableName, int& count)
    {

        T::getCount(tableName, count);
    }

    template<typename T>
    void updateItem(const std::string& tableName, const nlohmann::json& item)
    {
        T::updateItem(tableName, item);
    }

    template<typename T>
    void getDBItem(nlohmann::json& item, const nlohmann::json& query)
    {
        T::getDBItem(item, query);
    }
}

#endif

/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_HPP
#define _FIMDB_HPP
#include "dbsync.hpp"
#include "dbItem.hpp"
#include "rsync.hpp"
#include "shared.h"

enum class dbResult
{
    DB_SUCCESS,
    DB_ERROR
};

class FIMDB final
{
    public:
        static FIMDB& getInstance()
        {
            static FIMDB s_instance;
            return s_instance;
        };

        void init();
        void syncDB();
        bool isFull()
        {
            return m_isFull;
        };

#ifdef WIN32
    void init(const std::string& dbPath, const unsigned int interval_synchronization, const unsigned int max_rows_file, const unsigned int max_rows_registry);
#else
    void init(const std::string& dbPath, const unsigned int interval_synchronization, const unsigned int max_rows_file);
#endif
    int insertItem(DBItem const &item);
    int removeItem(DBItem const &item);
    int updateItem(DBItem const &item, ResultCallbackData callbackData);
    int setAllUnscanned();
    int executeQuery();

private:
    FIMDB();
    ~FIMDB() = default;
    FIMDB(const FIMDB&) = delete;

    const unsigned int            m_max_rows_file;
    const unsigned int            m_max_rows_registry;
    const unsigned int            m_interval_synchronization;
    std::unique_ptr<DBSync>       m_dbsyncHandler;
    std::unique_ptr<RemoteSync>   m_rsyncHandler;

    std::string createStatement();

protected:
    void setFileLimit();
    void setRegistryLimit();
    void setValueLimit();

};
#endif //_FIMDB_HPP

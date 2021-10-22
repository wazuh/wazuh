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
#include "fimDB.hpp"
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

        int insertItem(DBItem*);
        int removeItem(DBItem*);
        int updateItem(DBItem*);
        int setAllUnscanned();
        int executeQuery();

    private:
        FIMDB();
        ~FIMDB() = default;
        FIMDB(const FIMDB&) = delete;
        bool            m_isFull;
        DBSYNC_HANDLE   m_dbsyncHandler;
        RSYNC_HANDLE    m_rsyncHandler;
};
#endif //_FIMDB_HPP

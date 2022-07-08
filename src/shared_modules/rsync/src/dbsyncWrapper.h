/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBSYNC_WRAPPER_H
#define _DBSYNC_WRAPPER_H

#include "dbsync.hpp"
#include "json.hpp"

namespace RSync
{
    class DBSyncWrapper
    {
            DBSYNC_HANDLE m_dbsyncHandle;
        public:

            explicit DBSyncWrapper(DBSYNC_HANDLE dbsyncHandle)
                : m_dbsyncHandle(dbsyncHandle) { }
            virtual void select(nlohmann::json& data,
                                ResultCallbackData callbackData)
            {
                DBSync(m_dbsyncHandle).selectRows(data, callbackData);
            }
            // LCOV_EXCL_START
            virtual ~DBSyncWrapper() = default;
            // LCOV_EXCL_STOP
    };
};// namespace RSync


#endif //_DBSYNC_WRAPPER_H

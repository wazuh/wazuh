/*
 * Wazuh Syscheck - Test tool
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 21, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _TEST_CONTEXT_H
#define _TEST_CONTEXT_H
#include <mutex>
#include "dbsync.h"
#include "dbsync.hpp"

struct TestContext
{
    DBSYNC_HANDLE handle;
    std::unique_ptr<DBSyncTxn> txn;
    std::mutex txn_callback_mutex;
    size_t currentId;
    std::string outputPath;

    static std::string typeOperation(const ReturnTypeCallback result)
    {
        std::string opResult;
        switch(result)
        {
            case MODIFIED:
                opResult = "MODIFIED";
                break;
            case DELETED:
                opResult = "DELETED";
                break;
            case INSERTED:
                opResult = "INSERTED";
                break;
            case MAX_ROWS:
                opResult = "MAX_ROWS";
                break;
            case DB_ERROR:
                opResult = "DB_ERROR";
                break;
            case SELECTED:
                opResult = "SELECTED";
                break;
            case GENERIC:
                opResult = "GENERIC";
                break;
        }

        return opResult;
    }
};

#endif //_TEST_CONTEXT_H

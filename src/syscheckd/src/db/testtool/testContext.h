/*
 * Wazuh Syscheck - Test tool
 * Copyright (C) 2015, Wazuh Inc.
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

static const std::map<ReturnTypeCallback, std::string> RETURN_TYPE_OPERATION =
{
    { MODIFIED, "MODIFIED" },
    { DELETED,  "DELETED"  },
    { INSERTED, "INSERTED" },
    { MAX_ROWS, "MAX_ROWS" },
    { DB_ERROR, "DB_ERROR" },
    { SELECTED, "SELECTED" },
    { GENERIC,  "GENERIC"  }
};

struct TestContext
{
    DBSYNC_HANDLE handle;
    std::unique_ptr<DBSyncTxn> txn;
    std::mutex txn_callback_mutex;
    size_t currentId;
    std::string outputPath;

};

#endif //_TEST_CONTEXT_H

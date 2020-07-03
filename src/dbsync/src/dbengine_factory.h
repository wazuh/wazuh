/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once
#include "db_exception.h"
#include "sqlite/sqlite_dbengine.h"
#include "sqlite/sqlite_wrapper_factory.h"
#include "typedef.h"
#include <iostream>

namespace DbSync
{
    class FactoryDbEngine
    {
    public:
        static std::unique_ptr<IDbEngine> create(const DbEngineType dbType,
                                                 const std::string& path,
                                                 const std::string& sqlStatement)
        {
            if (SQLITE3 == dbType)
            {
                return std::make_unique<SQLiteDBEngine>(std::make_shared<SQLiteFactory>(), path, sqlStatement);
            }
            throw dbsync_error
            {
                1, "Unspecified type during factory instantiation"
            };
        }
    };
}// namespace DbSync

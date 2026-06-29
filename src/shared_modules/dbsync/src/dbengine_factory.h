/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBENGINE_FACTORY_H
#define _DBENGINE_FACTORY_H

#include "db_exception.h"
#include "sqlite/sqlite_dbengine.h"
#include "sqlite/sqlite_wrapper_factory.h"
#include "commonDefs.h"
#include <iostream>

namespace DbSync
{
    class FactoryDbEngine
    {
        public:
            static std::unique_ptr<IDbEngine> create(const DbEngineType              dbType,
                                                     const std::string&              path,
                                                     const std::string&              sqlStatement,
                                                     const DbManagement              dbManagement,
                                                     const std::vector<std::string>& upgradeStatements)
            {
                if (SQLITE3 == dbType)
                {
                    return std::make_unique<SQLiteDBEngine>(std::make_shared<SQLiteFactory>(), path, sqlStatement, dbManagement, upgradeStatements);
                }

                throw dbsync_error
                {
                    FACTORY_INSTANTATION
                };
            }
    };
}// namespace DbSync

#endif // _DBENGINE_FACTORY_H

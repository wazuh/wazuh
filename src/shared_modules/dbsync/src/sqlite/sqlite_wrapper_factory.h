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

#ifndef _SQLITE_WRAPPER_FACTORY_H
#define _SQLITE_WRAPPER_FACTORY_H

#include "sqlite_wrapper.h"
#include "makeUnique.h"
class ISQLiteFactory
{
    public:
        // LCOV_EXCL_START
        virtual ~ISQLiteFactory() = default;
        // LCOV_EXCL_STOP
        virtual std::shared_ptr<SQLite::IConnection> createConnection(const std::string& path) = 0;
        virtual std::unique_ptr<SQLite::ITransaction> createTransaction(std::shared_ptr<SQLite::IConnection>& connection) = 0;
        virtual std::unique_ptr<SQLite::IStatement> createStatement(std::shared_ptr<SQLite::IConnection>& connection,
                                                                    const std::string& query) = 0;
};

class SQLiteFactory : public ISQLiteFactory
{
    public:
        SQLiteFactory() = default;
        // LCOV_EXCL_START
        ~SQLiteFactory() = default;
        // LCOV_EXCL_STOP
        SQLiteFactory(const SQLiteFactory&) = delete;
        SQLiteFactory& operator=(const SQLiteFactory&) = delete;

        std::shared_ptr<SQLite::IConnection> createConnection(const std::string& path) override
        {
            return std::make_shared<SQLite::Connection>(path);
        }
        std::unique_ptr<SQLite::ITransaction> createTransaction(std::shared_ptr<SQLite::IConnection>& connection) override
        {
            return std::make_unique<SQLite::Transaction>(connection);
        }

        std::unique_ptr<SQLite::IStatement> createStatement(std::shared_ptr<SQLite::IConnection>& connection,
                                                            const std::string& query) override
        {
            return std::make_unique<SQLite::Statement>(connection, query);
        }
};

#endif // _SQLITE_WRAPPER_FACTORY_H

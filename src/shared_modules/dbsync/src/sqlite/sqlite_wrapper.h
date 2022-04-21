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

#ifndef _SQLITE_WRAPPER_H
#define _SQLITE_WRAPPER_H

#include "isqlite_wrapper.h"
#include "sqlite3.h"

#include <string>
#include <memory>
namespace SQLite
{
    class Connection : public IConnection
    {
        public:
            Connection();
            ~Connection() = default;
            explicit Connection(const std::string& path);

            void execute(const std::string& query) override;
            void close() override;
            const std::shared_ptr<sqlite3>& db() const override;
            int64_t changes() const override;
        private:
            std::shared_ptr<sqlite3> m_db;
    };


    class Transaction : public ITransaction
    {
        public:
            ~Transaction();
            explicit Transaction(std::shared_ptr<IConnection>& connection);

            void commit() override;
            void rollback() override;
            bool isRolledBack() const;
            bool isCommited() const;
        private:
            std::shared_ptr<IConnection> m_connection;
            bool m_rolledBack;
            bool m_commited;
    };

    class Column : public IColumn
    {
        public:
            ~Column() = default;
            Column(std::shared_ptr<sqlite3_stmt>& stmt, const int32_t index);

            bool hasValue() const override;
            int32_t type() const override;
            std::string name() const override;
            int32_t value(const int32_t&) const override;
            uint64_t value(const uint64_t&) const override;
            int64_t value(const int64_t&) const override;
            std::string value(const std::string&) const override;
            double_t value(const double_t&) const override;
        private:
            std::shared_ptr<sqlite3_stmt> m_stmt;
            const int32_t m_index;
    };

    class Statement : public IStatement
    {
        public:
            ~Statement() = default;
            Statement(std::shared_ptr<IConnection>& connection,
                      const std::string& query);

            int32_t step() override;
            void reset() override;

            void bind(const int32_t index, const int32_t value) override;
            void bind(const int32_t index, const uint64_t value) override;
            void bind(const int32_t index, const int64_t value) override;
            void bind(const int32_t index, const std::string& value) override;
            void bind(const int32_t index, const double_t value) override;
            int columnsCount() const override;

            std::string expand() override;

            std::unique_ptr<IColumn> column(const int32_t index) override;

        private:
            std::shared_ptr<IConnection> m_connection;
            std::shared_ptr<sqlite3_stmt> m_stmt;
            const int m_bindParametersCount;
            int m_bindParametersIndex;
    };
}

#endif // _SQLITE_WRAPPER_H

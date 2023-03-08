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

#pragma once
#include <string>
#include <sqlite3.h>
#include <memory>
#include <math.h>
#include "db_exception.h"

namespace SQLite
{
    const constexpr auto MAX_ROWS_ERROR_STRING {"Too Many Rows."};

    class sqlite_error : public DbSync::dbsync_error
    {
        public:
            explicit sqlite_error(const std::pair<const int, const std::string>& exceptionInfo)
                : DbSync::dbsync_error
            {
                exceptionInfo.first, "sqlite: " + exceptionInfo.second
            }
            {}
    };

    class IConnection
    {
        public:
            // LCOV_EXCL_START
            virtual ~IConnection() = default;
            // LCOV_EXCL_STOP
            virtual void close() = 0;
            virtual void execute(const std::string& query) = 0;
            virtual int64_t changes() const = 0;
            virtual const std::shared_ptr<sqlite3>& db() const = 0;
    };

    class ITransaction
    {
        public:
            // LCOV_EXCL_START
            virtual ~ITransaction() = default;
            // LCOV_EXCL_STOP
            virtual void commit() = 0;
            virtual void rollback() = 0;
    };

    class IColumn
    {
        public:
            // LCOV_EXCL_START
            virtual ~IColumn() = default;
            // LCOV_EXCL_STOP
            virtual int32_t type() const = 0;
            virtual std::string name() const = 0;
            virtual bool hasValue() const = 0;
            virtual int32_t value(const int32_t&) const = 0;
            virtual uint64_t value(const uint64_t&) const = 0;
            virtual int64_t value(const int64_t&) const = 0;
            virtual std::string value(const std::string&) const = 0;
            virtual double_t value(const double_t&) const = 0;
    };

    class IStatement
    {
        public:
            // LCOV_EXCL_START
            virtual ~IStatement() = default;
            // LCOV_EXCL_STOP
            virtual int32_t step() = 0;
            virtual void bind(const int32_t index, const int32_t value) = 0;
            virtual void bind(const int32_t index, const uint64_t value) = 0;
            virtual void bind(const int32_t index, const int64_t value) = 0;
            virtual void bind(const int32_t index, const std::string& value) = 0;
            virtual void bind(const int32_t index, const double_t value) = 0;
            virtual int columnsCount() const = 0;

            virtual std::string expand() = 0;

            virtual std::unique_ptr<IColumn> column(const int32_t index) = 0;
            virtual void reset() = 0;

    };

}//namespace SQLite

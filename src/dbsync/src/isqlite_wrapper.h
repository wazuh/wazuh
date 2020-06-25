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
#include <string>
#include <sqlite3.h>
#include <memory>

namespace SQLite
{
    class IConnection
    {
    public:
        virtual ~IConnection() = default;
        virtual bool close() = 0;
        virtual bool execute(const std::string& query) = 0;
        virtual const std::shared_ptr<sqlite3>& db() const = 0;
    };

    class ITransaction
    {
    public:
        virtual ~ITransaction() = default;
        virtual bool commit() = 0;
        virtual bool rollback() = 0;
    };

    class IColumn
    {
    public:
        virtual ~IColumn() = default;
        virtual bool hasValue() const = 0;
        virtual int32_t value(const int32_t&) const = 0;
        virtual uint64_t value(const uint64_t&) const = 0;
        virtual int64_t value(const int64_t&) const = 0;
        virtual std::string value(const std::string&) const = 0;
        virtual double value(const double&) const = 0;
    };

    class IStatement
    {
    public:
        virtual ~IStatement() = default;
        virtual int32_t step() = 0;
        virtual bool bind(const int32_t index, const int32_t value) = 0;
        virtual bool bind(const int32_t index, const uint64_t value) = 0;
        virtual bool bind(const int32_t index, const int64_t value) = 0;
        virtual bool bind(const int32_t index, const std::string& value) = 0;
        virtual bool bind(const int32_t index, const double value) = 0;

        virtual std::unique_ptr<IColumn> column(const int32_t index) = 0;
        virtual bool reset() = 0;

    };

}//namespace SQLite
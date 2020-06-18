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

namespace SQLite {
class IConnection 
{
public:
    virtual ~IConnection() = default;
    virtual bool Close() = 0;
    virtual bool Execute(const std::string& query) = 0;
    virtual sqlite3* GetDBInstance() = 0;
};

class ITransaction 
{
public:
    virtual ~ITransaction() = default;
    virtual bool Commit() = 0;
    virtual bool Rollback() = 0;
};

class IColumn {
public:
    virtual ~IColumn() = default;
    virtual bool IsNullValue() = 0;
    virtual int32_t Int() = 0;
    virtual uint64_t UInt64() = 0;
    virtual int64_t Int64() = 0;
    virtual double Double() = 0;
    virtual std::string String() = 0;
};

class IStatement 
{
public:
    virtual ~IStatement() = default;
    virtual int32_t Step() = 0;
    virtual bool Bind(const int32_t index, const int32_t value) = 0;
    virtual bool Bind(const int32_t index, const uint64_t value) = 0;
    virtual bool Bind(const int32_t index, const int64_t value) = 0;
    virtual bool Bind(const int32_t index, const std::string value) = 0;
    virtual bool Bind(const int32_t index, const double value) = 0;

    virtual std::unique_ptr<IColumn> GetColumn(const int32_t index) = 0;
    virtual bool Reset() = 0;

};

}
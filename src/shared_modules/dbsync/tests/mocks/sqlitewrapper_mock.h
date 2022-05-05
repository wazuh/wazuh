/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCKSQLITEWRAPPER_TEST_H
#define _MOCKSQLITEWRAPPER_TEST_H

#include <gmock/gmock.h>
#include <string>
#include "sqlite/isqlite_wrapper.h"

class MockConnection : public SQLite::IConnection
{
    public:
        MockConnection() = default;
        virtual ~MockConnection() = default;
        MOCK_METHOD(void,
                    close,
                    (),
                    (override));
        MOCK_METHOD(void,
                    execute,
                    (const std::string& query),
                    (override));
        MOCK_METHOD(int64_t,
                    changes,
                    (),
                    (const override));
        MOCK_METHOD(const std::shared_ptr<sqlite3>&,
                    db,
                    (),
                    (const override));

};

class MockTransaction : public SQLite::ITransaction
{
    public:
        MOCK_METHOD(void,
                    commit,
                    (),
                    (override));
        MOCK_METHOD(void,
                    rollback,
                    (),
                    (override));
};

class MockColumn : public SQLite::IColumn
{
    public:
        MOCK_METHOD(bool,
                    hasValue,
                    (),
                    (const override));
        MOCK_METHOD(int32_t,
                    type,
                    (),
                    (const override));
        MOCK_METHOD(std::string,
                    name,
                    (),
                    (const override));
        MOCK_METHOD(int32_t,
                    value,
                    (const int32_t&),
                    (const override));
        MOCK_METHOD(uint64_t,
                    value,
                    (const uint64_t&),
                    (const override));
        MOCK_METHOD(int64_t,
                    value,
                    (const int64_t&),
                    (const override));
        MOCK_METHOD(std::string,
                    value,
                    (const std::string&),
                    (const override));
        MOCK_METHOD(double_t,
                    value,
                    (const double_t&),
                    (const override));
};

class MockStatement : public SQLite::IStatement
{
    public:
        MockStatement() = default;
        virtual ~MockStatement() = default;
        MOCK_METHOD(int32_t,
                    step,
                    (),
                    (override));
        MOCK_METHOD(void,
                    bind,
                    (const int32_t index, const int32_t value),
                    (override));
        MOCK_METHOD(void,
                    bind,
                    (const int32_t index, const uint64_t value),
                    (override));
        MOCK_METHOD(void,
                    bind,
                    (const int32_t index, const int64_t value),
                    (override));
        MOCK_METHOD(void,
                    bind,
                    (const int32_t index, const std::string& value),
                    (override));
        MOCK_METHOD(void,
                    bind,
                    (const int32_t index, const double_t value),
                    (override));

        MOCK_METHOD(std::string,
                    expand,
                    (),
                    (override));

        MOCK_METHOD(std::unique_ptr<SQLite::IColumn>,
                    column,
                    (const int32_t index),
                    (override));

        MOCK_METHOD(void,
                    reset,
                    (),
                    (override));
        MOCK_METHOD(int,
                    columnsCount,
                    (),
                    (const override));
};

#endif //_MOCKSQLITEWRAPPER_TEST_H

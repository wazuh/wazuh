/*
 * Wazuh SQLITE3 Wrapper
 * Copyright (C) 2015, Wazuh Inc.
 * May 5, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SQLITE3WRAPPERMOCK_HPP
#define _SQLITE3WRAPPERMOCK_HPP

#include <gmock/gmock.h>
class MockSQLiteConnection
{
public:
    MockSQLiteConnection() = default;
    ~MockSQLiteConnection() = default;

    // Mock methods for SQLite connection
};

class MockSQLiteStatement
{
public:
    MockSQLiteStatement() = default;
    ~MockSQLiteStatement() = default;

    MockSQLiteStatement(const MockSQLiteConnection& db, const std::string& query) {}

    MOCK_METHOD(int, step, (), (const));
    MOCK_METHOD(int64_t, valueInt64, (int index), ());
    MOCK_METHOD(std::string, valueString, (int index), ());

    template<typename T>
    T value(int index)
    {
        if constexpr (std::is_same_v<T, int64_t>)
        {
            return valueInt64(index);
        }
        else if (std::is_same_v<T, std::string>)
        {
            return valueString(index);
        }
        else
        {
            throw std::runtime_error("Unsupported type");
        }
    }

    MOCK_METHOD(void, bindString, (int index, std::string value), ());
    MOCK_METHOD(void, bindStringView, (int index, std::string_view value), ());
    MOCK_METHOD(void, bindInt64, (int index, int64_t value), ());
    MOCK_METHOD(void, bindInt32, (int index, int32_t value), ());
    MOCK_METHOD(void, reset, (), ());

    template<typename T>
    void bind(int index, const T& value)
    {
        if constexpr (std::is_same_v<T, std::string>)
        {
            bindString(index, value);
        }
        else if constexpr (std::is_same_v<T, std::string_view>)
        {
            bindStringView(index, value);
        }
        else if constexpr (std::is_same_v<T, int64_t>)
        {
            bindInt64(index, value);
        }
        else if constexpr (std::is_same_v<T, int32_t>)
        {
            bindInt32(index, value);
        }
        else
        {
            throw std::runtime_error("Unsupported type");
        }
    }
};

/**
 * @brief Trampoline class for SQLiteStatement class.
 */
class TrampolineSQLiteStatement final
{
public:
    TrampolineSQLiteStatement(const MockSQLiteConnection& db, const std::string& query)
    {
        m_queriesRef->push_back(query);
    }

    int step() const
    {
        return m_stmtRef->step();
    }

    template<typename T>
    T value(int index)
    {
        return m_stmtRef->value<T>(index);
    }

    // Mock method to simulate binding values
    template<typename T>
    void bind(int index, const T& value)
    {
        m_stmtRef->bind(index, value);
    }

    void reset()
    {
        m_stmtRef.reset();
    }

    // Dependency injection setup
    static void inject(std::shared_ptr<MockSQLiteStatement> stmt, std::shared_ptr<std::vector<std::string>> queries)
    {
        m_stmtRef = std::move(stmt);
        m_queriesRef = std::move(queries);
    }

private:
    inline static std::shared_ptr<MockSQLiteStatement> m_stmtRef;
    inline static std::shared_ptr<std::vector<std::string>> m_queriesRef;
};
#endif //_SQLITE3WRAPPERMOCK_HPP

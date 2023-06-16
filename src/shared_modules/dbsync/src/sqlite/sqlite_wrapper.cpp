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

#include "sqlite_wrapper.h"
#include "db_exception.h"
#include "makeUnique.h"
#include "customDeleter.hpp"
#include <iostream>
#include <chrono>
#include <sys/stat.h>

constexpr auto DB_DEFAULT_PATH {"temp.db"};
constexpr auto DB_MEMORY {":memory:"};
constexpr auto DB_PERMISSIONS
{
    0640
};

using namespace SQLite;
using ExpandedSQLPtr = std::unique_ptr<char, CustomDeleter<decltype(&sqlite3_free), sqlite3_free>>;

static void checkSqliteResult(const int result,
                              const std::string& exceptionString)
{
    if (SQLITE_OK != result)
    {
        throw sqlite_error
        {
            std::make_pair(result, exceptionString)
        };
    }
}

static sqlite3* openSQLiteDb(const std::string& path, const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
{
    sqlite3* pDb{ nullptr };
    const auto result
    {
        sqlite3_open_v2(path.c_str(), &pDb, flags, nullptr)
    };
    checkSqliteResult(result, "Unspecified type during initialization of SQLite.");
    return pDb;
}

Connection::Connection(const std::string& path)
    : m_db{ openSQLiteDb(path), [](sqlite3 * p)
{
    sqlite3_close_v2(p);
} }
{
#ifndef _WIN32

    if (path.compare(DB_MEMORY) != 0)
    {
        const auto result { chmod(path.c_str(), DB_PERMISSIONS) };

        if (result != 0)
        {
            throw sqlite_error
            {
                std::make_pair(result, "Error changing permissions of SQLite database.")
            };
        }

        m_db.reset(openSQLiteDb(path, SQLITE_OPEN_READWRITE), [](sqlite3 * p)
        {
            sqlite3_close_v2(p);
        });
    }

#endif
}

void Connection::close()
{
    m_db.reset();
}

const std::shared_ptr<sqlite3>& Connection::db() const
{
    return m_db;
}

Connection::Connection()
    : Connection(DB_DEFAULT_PATH)
{}

void Connection::execute(const std::string& query)
{
    if (!m_db)
    {
        throw sqlite_error
        {
            SQLITE_CONNECTION_ERROR
        };
    }

    const auto result
    {
        sqlite3_exec(m_db.get(), query.c_str(), 0, 0, nullptr)
    };

    checkSqliteResult(result, query + ". " + sqlite3_errmsg(m_db.get()));
}

int64_t Connection::changes() const
{
    return sqlite3_changes(m_db.get());
}

Transaction::~Transaction()
{
    try
    {
        if (!m_rolledBack && !m_commited)
        {
            m_connection->execute("ROLLBACK TRANSACTION");
        }
    }
    //dtor should never throw
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP
}

Transaction::Transaction(std::shared_ptr<IConnection>& connection)
    : m_connection{ connection }
    , m_rolledBack{ false }
    , m_commited{ false }
{
    m_connection->execute("BEGIN TRANSACTION");
}

void Transaction::commit()
{
    if (!m_rolledBack && !m_commited)
    {
        m_connection->execute("COMMIT TRANSACTION");
        m_commited = true;
    }
}

void Transaction::rollback()
{
    try
    {
        if (!m_rolledBack && !m_commited)
        {
            m_rolledBack = true;
            m_connection->execute("ROLLBACK TRANSACTION");
        }
    }
    //rollback can be called in a catch statement to unwind things so it shouldn't throw
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP
}

bool Transaction::isCommited() const
{
    return m_commited;
}

bool Transaction::isRolledBack() const
{
    return m_rolledBack;
}

static sqlite3_stmt* prepareSQLiteStatement(std::shared_ptr<IConnection>& connection,
                                            const std::string& query)
{
    sqlite3_stmt* pStatement{ nullptr };
    const auto result
    {
        sqlite3_prepare_v2(connection->db().get(), query.c_str(), -1, &pStatement, nullptr)
    };
    checkSqliteResult(result, sqlite3_errmsg(connection->db().get()));
    return pStatement;
}

Statement::Statement(std::shared_ptr<IConnection>& connection,
                     const std::string& query)
    : m_connection{ connection }
    , m_stmt{ prepareSQLiteStatement(m_connection, query), [](sqlite3_stmt * p)
{
    sqlite3_finalize(p);
} }
, m_bindParametersCount{ sqlite3_bind_parameter_count(m_stmt.get()) }
, m_bindParametersIndex{ 0 }
{}

int32_t Statement::step()
{
    auto ret { SQLITE_ERROR };

    if (m_bindParametersIndex == m_bindParametersCount)
    {
        ret = sqlite3_step(m_stmt.get());

        if (SQLITE_ROW != ret && SQLITE_DONE != ret)
        {
            checkSqliteResult(ret, sqlite3_errmsg(m_connection->db().get()));
        }
    }

    return ret;
}

void Statement::reset()
{
    sqlite3_reset(m_stmt.get());
    m_bindParametersIndex = 0;
}

void Statement::bind(const int32_t index, const int32_t value)
{
    const auto result{ sqlite3_bind_int(m_stmt.get(), index, value) };
    checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
    ++m_bindParametersIndex;
}
void Statement::bind(const int32_t index, const uint64_t value)
{
    const auto result{ sqlite3_bind_int64(m_stmt.get(), index, value) };
    checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
    ++m_bindParametersIndex;
}
void Statement::bind(const int32_t index, const int64_t value)
{
    const auto result{ sqlite3_bind_int64(m_stmt.get(), index, value) };
    checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
    ++m_bindParametersIndex;
}
void Statement::bind(const int32_t index, const std::string& value)
{
    const auto result
    {
        sqlite3_bind_text(m_stmt.get(),
                          index,
                          value.c_str(),
                          value.length(),
                          SQLITE_TRANSIENT)
    };
    checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
    ++m_bindParametersIndex;
}
void Statement::bind(const int32_t index, const double_t value)
{
    const auto result{ sqlite3_bind_double(m_stmt.get(), index, value) };
    checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
    ++m_bindParametersIndex;
}

// LCOV_EXCL_START
std::string Statement::expand()
{
    return ExpandedSQLPtr(sqlite3_expanded_sql(m_stmt.get())).get();
}
// LCOV_EXCL_STOP

std::unique_ptr<IColumn> Statement::column(const int32_t index)
{
    return std::make_unique<SQLite::Column>(m_stmt, index);
}

int Statement::columnsCount() const
{
    return sqlite3_column_count(m_stmt.get());
}
Column::Column(std::shared_ptr<sqlite3_stmt>& stmt,
               const int32_t index)
    : m_stmt{ stmt }
    , m_index{ index }
{}

bool Column::hasValue() const
{
    return SQLITE_NULL != sqlite3_column_type(m_stmt.get(), m_index);
}
int32_t Column::type() const
{
    return sqlite3_column_type(m_stmt.get(), m_index);
}
std::string Column::name() const
{
    return sqlite3_column_name(m_stmt.get(), m_index);
}
int32_t Column::value(const int32_t&) const
{
    return sqlite3_column_int(m_stmt.get(), m_index);
}
uint64_t Column::value(const uint64_t&) const
{
    return sqlite3_column_int64(m_stmt.get(), m_index);
}
int64_t Column::value(const int64_t&) const
{
    return sqlite3_column_int64(m_stmt.get(), m_index);
}
double_t Column::value(const double_t&) const
{
    return sqlite3_column_double(m_stmt.get(), m_index);
}
std::string Column::value(const std::string&) const
{
    const auto str { reinterpret_cast<const char*>(sqlite3_column_text(m_stmt.get(), m_index)) };
    return nullptr != str ? str : "";
}

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

#include "sqlite_wrapper.h"
#include <iostream>
#include <chrono>

constexpr auto DB_DEFAULT_PATH {"temp.db"};

using namespace SQLite;

static sqlite3* openSQLiteDb(const std::string& path)
{
    sqlite3* pDb{ nullptr };
    const auto ret
    {
        sqlite3_open_v2(path.c_str(), &pDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr)
    };
    if (SQLITE_OK != ret)
    {
        throw SQLite::exception
        {
            600,
            "Unspecified type during initialization of SQLite."
        };
    }
    return pDb;
}

Connection::Connection(const std::string& path)
: m_db{ openSQLiteDb(path), [](sqlite3* p){ sqlite3_close_v2(p); } }
{}

bool Connection::close()
{
    m_db.reset();
    return !m_db;
}

const std::shared_ptr<sqlite3>& Connection::db() const
{
    return m_db;
}

Connection::Connection()
: Connection(DB_DEFAULT_PATH)
{}

bool Connection::execute(const std::string& query)
{
    return m_db &&
           SQLITE_OK == sqlite3_exec(m_db.get(), query.c_str(), 0,0, nullptr);
}

Transaction::~Transaction()
{
    if (!m_rolledBack && !m_commited)
    {
        m_connection->execute("ROLLBACK TRANSACTION");
    }
}

Transaction::Transaction(std::shared_ptr<IConnection>& connection)
: m_connection{ connection }
, m_rolledBack{ false }
, m_commited{ false }
{
    if (!m_connection->execute("BEGIN TRANSACTION"))
    {
        throw SQLite::exception
        {
            601,
            "cannot begin SQLite Transaction."
        };
    }
}
    
bool Transaction::commit()
{
    bool ret{ false };
    if (!m_rolledBack && !m_commited)
    {
        ret = m_connection->execute("COMMIT TRANSACTION");
        m_commited = ret;
    }
    return ret;
}

bool Transaction::rollback()
{
    if (!m_rolledBack && !m_commited)
    {
        m_connection->execute("ROLLBACK TRANSACTION");
        m_rolledBack = true;
    }
    return m_rolledBack;
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
    const auto ret
    {
        sqlite3_prepare_v2(connection->db().get(), query.c_str(), -1, &pStatement, nullptr)
    };
    if(SQLITE_OK != ret)
    {
        throw SQLite::exception
        {
            602, "cannot instance SQLite stmt."
        };
    }
    return pStatement;
}

Statement::Statement(std::shared_ptr<IConnection>& connection,
                     const std::string& query)
: m_connection{ connection }
, m_stmt{ prepareSQLiteStatement(m_connection, query), [](sqlite3_stmt* p){ sqlite3_finalize(p); } }
{}

int32_t Statement::step()
{
    const auto ret { sqlite3_step(m_stmt.get()) };
    if (SQLITE_ROW != ret && SQLITE_DONE != ret)
    {
        throw SQLite::exception
        {
            603, sqlite3_errmsg(m_connection->db().get())
        };
    }
    return ret;
}
bool Statement::reset()
{
    return SQLITE_OK == sqlite3_reset(m_stmt.get());
}

bool Statement::bind(const int32_t index, const int32_t value)
{
    return SQLITE_OK == sqlite3_bind_int(m_stmt.get(), index, value);
}
bool Statement::bind(const int32_t index, const uint64_t value)
{
    return SQLITE_OK == sqlite3_bind_int64(m_stmt.get(), index, value);
}
bool Statement::bind(const int32_t index, const int64_t value)
{
    return SQLITE_OK == sqlite3_bind_int64(m_stmt.get(), index, value);
}
bool Statement::bind(const int32_t index, const std::string& value)
{
    return SQLITE_OK == sqlite3_bind_text(m_stmt.get(),
                                          index,
                                          value.c_str(),
                                          value.length(),
                                          SQLITE_TRANSIENT);
}
bool Statement::bind(const int32_t index, const double value)
{
    return SQLITE_OK == sqlite3_bind_double(m_stmt.get(), index, value);
}

std::unique_ptr<IColumn> Statement::column(const int32_t index)
{
    return std::make_unique<SQLite::Column>(m_stmt, index);
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
double Column::value(const double&) const
{
    return sqlite3_column_double(m_stmt.get(), m_index);
}
std::string Column::value(const std::string&) const
{
    const auto str { reinterpret_cast<const char *>(sqlite3_column_text(m_stmt, m_index)) };
    return nullptr != str ? str : "";
}

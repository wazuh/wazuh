/*
 * Wazuh SQLITE3 wrapper
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SQLITE3_WRAPPER_HPP
#define _SQLITE3_WRAPPER_HPP

#include "external/sqlite/sqlite3.h"
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <sys/stat.h>

constexpr auto DB_DEFAULT_PATH {"temp.db"};
constexpr auto DB_MEMORY {":memory:"};
constexpr auto DB_PERMISSIONS {0640};

namespace SQLite
{
    class Sqlite3Error : public std::exception
    {
        const char* m_errorMessage;
    public:
        explicit Sqlite3Error(const char* errorMessage)
            : m_errorMessage(errorMessage)
        {
        }
        ~Sqlite3Error() override = default;
        const char* what() const noexcept override
        {
            return m_errorMessage;
        }
    };

    class Connection final
    {
        static void connectionDeleter(sqlite3* p)
        {
            std::cout << "SQLite connection deleter called." << std::endl;
            if (p == nullptr)
            {
                return;
            }
            sqlite3_close_v2(p);
        }
        static sqlite3* openSQLiteDb(const std::string& path,
                                     const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
        {
            sqlite3* pDb {nullptr};
            if (const auto result {sqlite3_open_v2(path.c_str(), &pDb, flags, nullptr)}; SQLITE_OK != result)
            {
                throw Sqlite3Error {"Unspecified type during initialization of SQLite."};
            }

            return pDb;
        }

    public:
        ~Connection() = default;
        explicit Connection(const std::string& path)
            : m_db {openSQLiteDb(path), &connectionDeleter}
        {
#ifndef _WIN32

            if (path.compare(DB_MEMORY) != 0)
            {
                if (const auto result {chmod(path.c_str(), DB_PERMISSIONS)}; result != 0)
                {
                    throw Sqlite3Error {"Error changing permissions of SQLite database."};
                }

                m_db.reset(openSQLiteDb(path, SQLITE_OPEN_READWRITE));
            }

#endif
        }
        explicit Connection(sqlite3* db)
            : m_db {nullptr, &connectionDeleter}
            , m_dbPtr {db}
        {
        }

        void close()
        {
            m_db.reset();
        }

        sqlite3* db() const
        {
            if (m_dbPtr)
            {
                return m_dbPtr;
            }
            else if (m_db)
            {
                return m_db.get();
            }
            else
            {
                return nullptr;
            }
        }

        void execute(const std::string& query) const
        {
            if (db() == nullptr)
            {
                throw Sqlite3Error {"SQLite not initialized."};
            }

            const auto result {sqlite3_exec(db(), query.c_str(), nullptr, nullptr, nullptr)};

            if (SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(db())};
            }
        }

        int64_t changes() const
        {
            return sqlite3_changes(db());
        }

    private:
        std::unique_ptr<sqlite3, decltype(&connectionDeleter)> m_db;
        sqlite3* m_dbPtr {nullptr};
    };

    class Statement final
    {
        static void statementDeleter(sqlite3_stmt* p)
        {
            if (p == nullptr)
            {
                return;
            }
            sqlite3_finalize(p);
        }

    public:
        ~Statement()
        {
            sqlite3_reset(m_stmt.get());
        }
        static sqlite3_stmt* prepareSQLiteStatement(const Connection& connection, std::string_view query)
        {
            sqlite3_stmt* pStatement {nullptr};
            if (const auto result {sqlite3_prepare_v2(
                    connection.db(), query.data(), static_cast<int>(query.size()), &pStatement, nullptr)};
                SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(connection.db())};
            }
            return pStatement;
        }

        Statement(const Connection& connection, std::string_view query)
            : m_connection {connection}
            , m_stmt {prepareSQLiteStatement(m_connection, query), &statementDeleter}
            , m_bindParametersCount {sqlite3_bind_parameter_count(m_stmt.get())}
        {
        }

        int32_t step() const
        {
            auto ret {SQLITE_ERROR};

            if (m_bindParametersIndex == m_bindParametersCount)
            {
                ret = sqlite3_step(m_stmt.get());

                if (SQLITE_ROW != ret && SQLITE_DONE != ret && SQLITE_OK != ret)
                {
                    throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
                }
            }

            return ret;
        }

        void reset()
        {
            sqlite3_reset(m_stmt.get());
            m_bindParametersIndex = 0;
        }

        void bind(const int32_t index, const int32_t value)
        {
            if (const auto result {sqlite3_bind_int(m_stmt.get(), index, value)}; SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
            }
            ++m_bindParametersIndex;
        }
        void bind(const int32_t index, const uint64_t value)
        {
            if (const auto result {sqlite3_bind_int64(m_stmt.get(), index, static_cast<sqlite3_int64>(value))};
                SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
            }
            ++m_bindParametersIndex;
        }
        void bind(const int32_t index, const int64_t value)
        {
            if (const auto result {sqlite3_bind_int64(m_stmt.get(), index, value)}; SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
            }
            ++m_bindParametersIndex;
        }
        void bind(const int32_t index, const std::string& value)
        {
            if (const auto result {sqlite3_bind_text(
                    m_stmt.get(), index, value.c_str(), static_cast<int>(value.length()), SQLITE_TRANSIENT)};
                SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
            }
            ++m_bindParametersIndex;
        }
        void bind(const int32_t index, std::string_view value)
        {
            if (const auto result {sqlite3_bind_text(
                    m_stmt.get(), index, value.data(), static_cast<int>(value.length()), SQLITE_TRANSIENT)};
                SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
            }
            ++m_bindParametersIndex;
        }
        void bind(const int32_t index, const double value)
        {
            if (const auto result {sqlite3_bind_double(m_stmt.get(), index, value)}; SQLITE_OK != result)
            {
                throw Sqlite3Error {sqlite3_errmsg(m_connection.db())};
            }
            ++m_bindParametersIndex;
        }

        template<typename T>
        T value(const int32_t index) const
        {
            if constexpr (std::is_same_v<T, int32_t>)
            {
                return sqlite3_column_int(m_stmt.get(), index);
            }
            else if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t>)
            {
                return sqlite3_column_int64(m_stmt.get(), index);
            }
            else if constexpr (std::is_same_v<T, double>)
            {
                return sqlite3_column_double(m_stmt.get(), index);
            }
            else if constexpr (std::is_same_v<T, std::string>)
            {
                const auto str {reinterpret_cast<const char*>(sqlite3_column_text(m_stmt.get(), index))};
                return nullptr != str ? str : "";
            }
        }
        bool hasValue(const int32_t index) const
        {
            return SQLITE_NULL != sqlite3_column_type(m_stmt.get(), index);
        }
        int32_t type(const int32_t index) const
        {
            return sqlite3_column_type(m_stmt.get(), index);
        }
        std::string name(const int32_t index) const
        {
            return sqlite3_column_name(m_stmt.get(), index);
        }

        int columnsCount() const
        {
            return sqlite3_column_count(m_stmt.get());
        }

        sqlite3_stmt* get() const
        {
            return m_stmt.get();
        }

    private:
        const Connection& m_connection;
        std::unique_ptr<sqlite3_stmt, decltype(&statementDeleter)> m_stmt;
        const int m_bindParametersCount;
        int m_bindParametersIndex {0};
    };
} // namespace SQLite

#endif // _SQLITE3_WRAPPER_HPP

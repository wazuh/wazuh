/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SQLITE_WRAPPER_TEMP_H
#define _SQLITE_WRAPPER_TEMP_H

#include "sqlite3.h"
#include <string>
#include <memory>
#include "makeUnique.h"
#include "customDeleter.hpp"
#include <iostream>
#include <chrono>
#include <sys/stat.h>
#include <math.h>
#include <stdexcept>

using DBSyncExceptionType = const std::pair<int, std::string>;

DBSyncExceptionType FACTORY_INSTANTATION           { std::make_pair(1, "Unspecified type during factory instantiation")         };
DBSyncExceptionType INVALID_HANDLE                 { std::make_pair(2, "Invalid handle value.")                                 };
DBSyncExceptionType INVALID_TRANSACTION            { std::make_pair(3, "Invalid transaction value.")                            };
DBSyncExceptionType SQLITE_CONNECTION_ERROR        { std::make_pair(4, "No connection available for executions.")               };
DBSyncExceptionType EMPTY_DATABASE_PATH            { std::make_pair(5, "Empty database store path.")                            };
DBSyncExceptionType EMPTY_TABLE_METADATA           { std::make_pair(6, "Empty table metadata.")                                 };
DBSyncExceptionType INVALID_PARAMETERS             { std::make_pair(7, "Invalid parameters.")                                   };
DBSyncExceptionType DATATYPE_NOT_IMPLEMENTED       { std::make_pair(8, "Datatype not implemented.")                             };
DBSyncExceptionType SQL_STMT_ERROR                 { std::make_pair(9, "Invalid SQL statement.")                                };
DBSyncExceptionType INVALID_PK_DATA                { std::make_pair(10, "Primary key not found.")                               };
DBSyncExceptionType INVALID_COLUMN_TYPE            { std::make_pair(11, "Invalid column field type.")                           };
DBSyncExceptionType INVALID_DATA_BIND              { std::make_pair(12, "Invalid data to bind.")                                };
DBSyncExceptionType INVALID_TABLE                  { std::make_pair(13, "Invalid table.")                                       };
DBSyncExceptionType INVALID_DELETE_INFO            { std::make_pair(14, "Invalid information provided for deletion.")           };
DBSyncExceptionType BIND_FIELDS_DOES_NOT_MATCH     { std::make_pair(15, "Invalid information provided for statement creation.") };
DBSyncExceptionType STEP_ERROR_CREATE_STMT         { std::make_pair(16, "Error creating table.")                                };
DBSyncExceptionType STEP_ERROR_ADD_STATUS_FIELD    { std::make_pair(17, "Error adding status field.")                           };
DBSyncExceptionType STEP_ERROR_UPDATE_STATUS_FIELD { std::make_pair(18, "Error updating status field.")                         };
DBSyncExceptionType STEP_ERROR_DELETE_STATUS_FIELD { std::make_pair(19, "Error deleting status field.")                         };
DBSyncExceptionType DELETE_OLD_DB_ERROR            { std::make_pair(20, "Error deleting old db.")                               };
DBSyncExceptionType MIN_ROW_LIMIT_BELOW_ZERO       { std::make_pair(21, "Invalid row limit, values below 0 not allowed.")       };
DBSyncExceptionType ERROR_COUNT_MAX_ROWS           { std::make_pair(22, "Count is less than 0.")                                };

namespace DbSync
{
    /**
     *   This class should be used by concrete types to report errors.
    */
    class dbsync_error : public std::exception
    {
        public:
            __attribute__((__returns_nonnull__))
            const char* what() const noexcept override
            {
                return m_error.what();
            }

            int id() const noexcept
            {
                return m_id;
            }

            dbsync_error(const int id,
                         const std::string& whatArg)
                : m_id{ id }
                , m_error{ whatArg }
            {}

            explicit dbsync_error(const std::pair<int, std::string>& exceptionInfo)
                : m_id{ exceptionInfo.first }
                , m_error{ exceptionInfo.second }
            {}

        private:
            /// an exception object as storage for error messages
            const int m_id;
            std::runtime_error m_error;
    };

    /**
     *   This class should be used by concrete types to report errors.
    */
    class max_rows_error : public std::exception
    {
        public:
            __attribute__((__returns_nonnull__))
            const char* what() const noexcept override
            {
                return m_error.what();
            }

            explicit max_rows_error(const std::string& whatArg)
                : m_error{ whatArg }
            {}

        private:
            /// an exception object as storage for error messages
            std::runtime_error m_error;
    };
}

constexpr auto DB_DEFAULT_PATH {"temp.db"};
constexpr auto DB_MEMORY {":memory:"};
constexpr auto DB_PERMISSIONS
{
    0640
};


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

namespace SQLite
{
    class Connection : public IConnection
    {
        public:
            ~Connection() = default;

            explicit Connection(const std::string& path)
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

            void close()
            {
                m_db.reset();
            }

            const std::shared_ptr<sqlite3>& db() const
            {
                return m_db;
            }

            Connection()
                : Connection(DB_DEFAULT_PATH)
            {}

            void execute(const std::string& query)
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

            int64_t changes() const
            {
                return sqlite3_changes(m_db.get());
            }
        private:
            std::shared_ptr<sqlite3> m_db;
    };

    class Transaction : public ITransaction
    {
        public:
            ~Transaction()
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

            explicit Transaction(std::shared_ptr<IConnection>& connection)
                : m_connection{ connection }
                , m_rolledBack{ false }
                , m_commited{ false }
            {
                m_connection->execute("BEGIN TRANSACTION");
            }

            void commit()
            {
                if (!m_rolledBack && !m_commited)
                {
                    m_connection->execute("COMMIT TRANSACTION");
                    m_commited = true;
                }
            }

            void rollback()
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

            bool isCommited() const
            {
                return m_commited;
            }

            bool isRolledBack() const
            {
                return m_rolledBack;
            }
        private:
            std::shared_ptr<IConnection> m_connection;
            bool m_rolledBack;
            bool m_commited;
    };

    class Column : public IColumn
    {
        public:
            ~Column() = default;
            Column(std::shared_ptr<sqlite3_stmt>& stmt,
                   const int32_t index)
                : m_stmt{ stmt }
                , m_index{ index }
            {}
            bool hasValue() const
            {
                return SQLITE_NULL != sqlite3_column_type(m_stmt.get(), m_index);
            }
            int32_t type() const
            {
                return sqlite3_column_type(m_stmt.get(), m_index);
            }
            std::string name() const
            {
                return sqlite3_column_name(m_stmt.get(), m_index);
            }
            int32_t value(const int32_t&) const
            {
                return sqlite3_column_int(m_stmt.get(), m_index);
            }
            uint64_t value(const uint64_t&) const
            {
                return sqlite3_column_int64(m_stmt.get(), m_index);
            }
            int64_t value(const int64_t&) const
            {
                return sqlite3_column_int64(m_stmt.get(), m_index);
            }
            double_t value(const double_t&) const
            {
                return sqlite3_column_double(m_stmt.get(), m_index);
            }
            std::string value(const std::string&) const
            {
                const auto str { reinterpret_cast<const char*>(sqlite3_column_text(m_stmt.get(), m_index)) };
                return nullptr != str ? str : "";
            }
        private:
            std::shared_ptr<sqlite3_stmt> m_stmt;
            const int32_t m_index;
    };

    class Statement : public IStatement
    {
        public:
            ~Statement() = default;
            Statement(std::shared_ptr<IConnection>& connection,
                      const std::string& query)
                : m_connection{ connection }
                , m_stmt{ prepareSQLiteStatement(m_connection, query), [](sqlite3_stmt * p)
            {
                sqlite3_finalize(p);
            } }
            , m_bindParametersCount{ sqlite3_bind_parameter_count(m_stmt.get()) }
            , m_bindParametersIndex{ 0 }
            {}

            int32_t step()
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

            void reset()
            {
                sqlite3_reset(m_stmt.get());
                m_bindParametersIndex = 0;
            }

            void bind(const int32_t index, const int32_t value)
            {
                const auto result{ sqlite3_bind_int(m_stmt.get(), index, value) };
                checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
                ++m_bindParametersIndex;
            }
            void bind(const int32_t index, const uint64_t value)
            {
                const auto result{ sqlite3_bind_int64(m_stmt.get(), index, value) };
                checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
                ++m_bindParametersIndex;
            }
            void bind(const int32_t index, const int64_t value)
            {
                const auto result{ sqlite3_bind_int64(m_stmt.get(), index, value) };
                checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
                ++m_bindParametersIndex;
            }
            void bind(const int32_t index, const std::string& value)
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
            void bind(const int32_t index, const double_t value)
            {
                const auto result{ sqlite3_bind_double(m_stmt.get(), index, value) };
                checkSqliteResult(result, sqlite3_errmsg(m_connection->db().get()));
                ++m_bindParametersIndex;
            }

            // LCOV_EXCL_START
            std::string expand()
            {
                return ExpandedSQLPtr(sqlite3_expanded_sql(m_stmt.get())).get();
            }
            // LCOV_EXCL_STOP

            std::unique_ptr<IColumn> column(const int32_t index)
            {
                return std::make_unique<SQLite::Column>(m_stmt, index);
            }

            int columnsCount() const
            {
                return sqlite3_column_count(m_stmt.get());
            }
        private:
            std::shared_ptr<IConnection> m_connection;
            std::shared_ptr<sqlite3_stmt> m_stmt;
            const int m_bindParametersCount;
            int m_bindParametersIndex;
    };
}

#endif // _SQLITE_WRAPPER_TEMP_H

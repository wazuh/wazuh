/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2021, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBSYNC_EXCEPTION_H
#define _DBSYNC_EXCEPTION_H
#include <stdexcept>
#include <string>

constexpr auto FACTORY_INSTANTATION           { std::make_pair(1, "Unspecified type during factory instantiation") };
constexpr auto INVALID_HANDLE                 { std::make_pair(2, "Invalid handle value.") };
constexpr auto INVALID_TRANSACTION            { std::make_pair(3, "Invalid transaction value.") };
constexpr auto SQLITE_CONNECTION_ERROR        { std::make_pair(4, "No connection available for executions.") };
constexpr auto EMPTY_DATABASE_PATH            { std::make_pair(5, "Empty database store path.") };
constexpr auto EMPTY_TABLE_METADATA           { std::make_pair(6, "Empty table metadata.") };
constexpr auto INVALID_PARAMETERS             { std::make_pair(7, "Invalid parameters.") };
constexpr auto DATATYPE_NOT_IMPLEMENTED       { std::make_pair(8, "Datatype not implemented.") };
constexpr auto SQL_STMT_ERROR                 { std::make_pair(9, "Invalid SQL statement.") };
constexpr auto INVALID_PK_DATA                { std::make_pair(10, "Primary key not found.") };
constexpr auto INVALID_COLUMN_TYPE            { std::make_pair(11, "Invalid column field type.") };
constexpr auto INVALID_DATA_BIND              { std::make_pair(12, "Invalid data to bind.") };
constexpr auto INVALID_TABLE                  { std::make_pair(13, "Invalid table.") };
constexpr auto INVALID_DELETE_INFO            { std::make_pair(14, "Invalid information provided for deletion.") };
constexpr auto BIND_FIELDS_DOES_NOT_MATCH     { std::make_pair(15, "Invalid information provided for statement creation.") };
constexpr auto STEP_ERROR_CREATE_STMT         { std::make_pair(16, "Error creating table.") };
constexpr auto STEP_ERROR_ADD_STATUS_FIELD    { std::make_pair(17, "Error adding status field.") };
constexpr auto STEP_ERROR_UPDATE_STATUS_FIELD { std::make_pair(18, "Error updating status field.") };
constexpr auto STEP_ERROR_DELETE_STATUS_FIELD { std::make_pair(19, "Error deleting status field.") };

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

#endif // _DBSYNC_EXCEPTION_H
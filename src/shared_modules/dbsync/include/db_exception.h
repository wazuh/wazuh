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

#ifndef _DBSYNC_EXCEPTION_H
#define _DBSYNC_EXCEPTION_H
#include <stdexcept>
#include <string>

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
DBSyncExceptionType STEP_ERROR_UPDATE_STMT         { std::make_pair(23, "Error upgrading DB.")                                  };

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

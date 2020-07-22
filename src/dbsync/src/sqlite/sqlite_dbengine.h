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

#ifndef _SQLITE_DBENGINE_H
#define _SQLITE_DBENGINE_H

#include <tuple>
#include <iostream>
#include "dbengine.h"
#include "sqlite_wrapper_factory.h"
#include "isqlite_wrapper.h"

constexpr auto TEMP_TABLE_SUBFIX {"_TEMP"};

constexpr auto STATUS_FIELD_NAME {"db_status_field_dm"};
constexpr auto STATUS_FIELD_TYPE {"INTEGER"};

const std::vector<std::string> InternalColumnNames = 
{
    { STATUS_FIELD_NAME }
};

enum ColumnType
{
    Unknown = 0,
    Text,
    Integer,
    BigInt,
    UnsignedBigInt,
    Double,
    Blob,
};

const std::map<ColumnType, std::string> kColumnTypeNames = 
{
    { Unknown        , "UNKNOWN"         },
    { Text           , "TEXT"            },
    { Integer        , "INTEGER"         },
    { BigInt         , "BIGINT"          },
    { UnsignedBigInt , "UNSIGNED BIGINT" },
    { Double         , "DOUBLE"          },
    { Blob           , "BLOB"            },
};

enum TableHeader 
{
    CID = 0,
    Name,
    Type,
    PK,
    TXNStatusField
}; 

using ColumnData = 
    std::tuple<int32_t, std::string, ColumnType, bool, bool>;

using TableColumns =
    std::vector<ColumnData>;

enum GenericTupleIndex
{
    GenType = 0,
    GenString,
    GenInteger,
    GenBigInt,
    GenUnsignedBigInt,
    GenDouble
}; 

using TableField = 
    std::tuple<int32_t, std::string, int32_t, int64_t, uint64_t, double_t>;

using Row = std::map<std::string, TableField>;

enum ResponseType
{
    RTJson = 0,
    RTCallback
}; 

class dbengine_error : public DbSync::dbsync_error
{
public:
    explicit dbengine_error(const std::pair<int, std::string>& exceptionInfo)
    : DbSync::dbsync_error
    { 
        exceptionInfo.first, "dbEngine: " + exceptionInfo.second
    }
    {}
};
class SQLiteDBEngine : public DbSync::IDbEngine 
{
    public:
        SQLiteDBEngine(const std::shared_ptr<ISQLiteFactory>& sqliteFactory,
                       const std::string& path,
                       const std::string& tableStmtCreation);
        ~SQLiteDBEngine();
        
        void bulkInsert(const std::string& table,
                        const nlohmann::json& data) override;

        void refreshTableData(const nlohmann::json& data,
                                      const DbSync::ResultCallback callback) override;

        void syncTableRowData(const std::string& table,
                              const nlohmann::json& data,
                              const DbSync::ResultCallback callback) override;

        void setMaxRows(const std::string& table,
                        const unsigned long long maxRows) override;

        virtual void initializeStatusField(const nlohmann::json& tableNames) override;

        virtual void deleteRowsByStatusField(const nlohmann::json& tableNames) override;

    private:
        void initialize(const std::string& path,
                        const std::string& tableStmtCreation);

        bool cleanDB(const std::string& path);

        size_t loadTableData(const std::string& table);

        bool loadFieldData(const std::string& table);

        std::string buildInsertBulkDataSqlQuery(const std::string& table);

        std::string buildDeleteBulkDataSqlQuery(const std::string& table, 
                                                const std::vector<std::string>& primaryKeyList);

        ColumnType columnTypeName(const std::string& type);

        void bindJsonData(std::unique_ptr<SQLite::IStatement>const & stmt, 
                          const ColumnData& cd,
                          const nlohmann::json::value_type& valueType);

        bool createCopyTempTable(const std::string& table);

        bool getTableCreateQuery(const std::string& table,
                                 std::string& resultQuery);

        bool getPrimaryKeysFromTable(const std::string& table,
                                     std::vector<std::string>& primaryKeyList);

        bool removeNotExistsRows(const std::string& table,
                                 const std::vector<std::string>& primaryKeyList,
                                 const DbSync::ResultCallback callback);

        bool insertNewRows(const std::string& table,
                           const std::vector<std::string>& primaryKeyList,
                           const DbSync::ResultCallback callback);

        bool deleteRows(const std::string& table,
                        const std::vector<std::string>& primaryKeyList,
                        const std::vector<Row>& rowsToRemove);

        int32_t getTableData(std::unique_ptr<SQLite::IStatement>const & stmt,
                             const int32_t index,
                             const ColumnType& type,
                             const std::string& fieldName,
                             Row& row);

        int32_t bindFieldData(std::unique_ptr<SQLite::IStatement>const & stmt,
                              const int32_t index,
                              const TableField& fieldData);

        std::string buildLeftOnlyQuery(const std::string& t1,
                                       const std::string& t2,
                                       const std::vector<std::string>& primaryKeyList,
                                       const bool returnOnlyPKFields = false);

        bool getLeftOnly(const std::string& t1,
                         const std::string& t2,
                         const std::vector<std::string>& primaryKeyList,
                         std::vector<Row>& returnRows);

        bool getPKListLeftOnly(const std::string& t1,
                               const std::string& t2,
                               const std::vector<std::string>& primaryKeyList,
                               std::vector<Row>& returnRows);

        void bulkInsert(const std::string& table, const std::vector<Row>& data);

        void deleteTempTable(const std::string& table);

        std::string buildModifiedRowsQuery(const std::string& t1,
                                           const std::string& t2,
                                           const std::vector<std::string>& primaryKeyList);

        int changeModifiedRows(const std::string& table,
                               const std::vector<std::string>& primaryKeyList,
                               const DbSync::ResultCallback callback);

        std::string buildUpdateDataSqlQuery(const std::string& table,
                                            const std::vector<std::string>& primaryKeyList,
                                            const Row& row,
                                            const std::pair<const std::string, TableField> &field);

        bool getRowsToModify(const std::string& table,
                             const std::vector<std::string>& primaryKeyList,
                             std::vector<Row>& rowKeysValue);

        bool updateRows(const std::string& table,
                        const std::vector<std::string>& primaryKeyList,
                        std::vector<Row>& rowKeysValue);

        bool getFieldValueFromTuple(const std::pair<const std::string, TableField> &value,
                                    std::string& resultValue,
                                    const bool quotationMarks = false);

        bool getFieldValueFromTuple(const std::pair<const std::string, TableField> &value,
                                    nlohmann::json& object);

        SQLiteDBEngine(const SQLiteDBEngine&) = delete;

        SQLiteDBEngine& operator=(const SQLiteDBEngine&) = delete;

        std::unique_ptr<SQLite::IStatement>const& getStatement(const std::string& sql);

        std::map<std::string, TableColumns> m_tableFields;
        std::map<std::string, std::unique_ptr<SQLite::IStatement>> m_statementsCache;
        std::shared_ptr<ISQLiteFactory> m_sqliteFactory;
        std::shared_ptr<SQLite::IConnection> m_sqliteConnection;

};

#endif // _SQLITE_DBENGINE_H

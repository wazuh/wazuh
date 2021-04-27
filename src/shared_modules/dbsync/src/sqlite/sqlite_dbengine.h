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

#ifndef _SQLITE_DBENGINE_H
#define _SQLITE_DBENGINE_H

#include <tuple>
#include <iostream>
#include <mutex>
#include <queue>
#include "dbengine.h"
#include "sqlite_wrapper_factory.h"
#include "isqlite_wrapper.h"
#include "mapWrapperSafe.h"

constexpr auto TEMP_TABLE_SUBFIX {"_TEMP"};

constexpr auto STATUS_FIELD_NAME {"db_status_field_dm"};
constexpr auto STATUS_FIELD_TYPE {"INTEGER"};

constexpr auto CACHE_STMT_LIMIT { 30ull };

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

const std::map<std::string, ColumnType> ColumnTypeNames =
{
    { "UNKNOWN"         , Unknown        },
    { "TEXT"            , Text           },
    { "INTEGER"         , Integer        },
    { "BIGINT"          , BigInt         },
    { "UNSIGNED BIGINT" , UnsignedBigInt },
    { "DOUBLE"          , Double         },
    { "BLOB"            , Blob           },
};

enum TableHeader 
{
    CID = 0,
    Name,
    Type,
    PK,
    TXNStatusField
}; 

enum GenericTupleIndex
{
    GenType = 0,
    GenString,
    GenInteger,
    GenBigInt,
    GenUnsignedBigInt,
    GenDouble
}; 

using ColumnData =
    std::tuple<int32_t, std::string, ColumnType, bool, bool>;

using TableColumns =
    std::vector<ColumnData>;

using TableField =
    std::tuple<int32_t, std::string, int32_t, int64_t, uint64_t, double_t>;

using Row = std::map<std::string, TableField>;

using Field = std::pair<const std::string, TableField>;

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


class SQLiteDBEngine final : public DbSync::IDbEngine 
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
                              const DbSync::ResultCallback callback,
                              const bool inTransaction = false) override;

        void setMaxRows(const std::string& table,
                        const unsigned long long maxRows) override;

        void initializeStatusField(const nlohmann::json& tableNames) override;

        void deleteRowsByStatusField(const nlohmann::json& tableNames) override;

        void returnRowsMarkedForDelete(const nlohmann::json& tableNames, 
                                       const DbSync::ResultCallback callback) override;

        void selectData(const std::string& table,
                        const nlohmann::json& query,
                        const DbSync::ResultCallback& callback) override;

        void deleteTableRowsData(const std::string& table,
                                 const nlohmann::json& jsDeletionData) override;
        
        void addTableRelationship(const nlohmann::json& data) override;

    private:
        void initialize(const std::string& path,
                        const std::string& tableStmtCreation);

        bool cleanDB(const std::string& path);

        size_t loadTableData(const std::string& table);

        bool loadFieldData(const std::string& table);

        std::string buildInsertBulkDataSqlQuery(const std::string& table,
                                                const nlohmann::json& data = {});

        std::string buildDeleteBulkDataSqlQuery(const std::string& table, 
                                                const std::vector<std::string>& primaryKeyList);

        std::string buildSelectQuery(const std::string& table,
                                     const nlohmann::json& jsQuery);

        ColumnType columnTypeName(const std::string& type);

        bool bindJsonData(const std::unique_ptr<SQLite::IStatement>& stmt,
                          const ColumnData& cd,
                          const nlohmann::json::value_type& valueType,
                          const unsigned int cid);

        bool createCopyTempTable(const std::string& table);

        bool getTableCreateQuery(const std::string& table,
                                 std::string& resultQuery);

        bool getPrimaryKeysFromTable(const std::string& table,
                                     std::vector<std::string>& primaryKeyList);

        bool removeNotExistsRows(const std::string& table,
                                 const std::vector<std::string>& primaryKeyList,
                                 const DbSync::ResultCallback callback);

        bool getRowDiff(const std::vector<std::string>& primaryKeyList,
                        const std::string& table,
                        const nlohmann::json& data,
                        nlohmann::json& jsResult);

        bool insertNewRows(const std::string& table,
                           const std::vector<std::string>& primaryKeyList,
                           const DbSync::ResultCallback callback);

        bool deleteRows(const std::string& table,
                        const std::vector<std::string>& primaryKeyList,
                        const std::vector<Row>& rowsToRemove);

        void deleteRows(const std::string& table,
                        const nlohmann::json& data,
                        const std::vector<std::string>& primaryKeyList);

        void deleteRowsbyPK(const std::string& table,
                            const nlohmann::json& data);

        void getTableData(std::unique_ptr<SQLite::IStatement>const & stmt,
                          const int32_t index,
                          const ColumnType& type,
                          const std::string& fieldName,
                          Row& row);

        void bindFieldData(const std::unique_ptr<SQLite::IStatement>& stmt,
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

        void bulkInsert(const std::string& table,
                        const std::vector<Row>& data);

        void deleteTempTable(const std::string& table);

        std::string buildModifiedRowsQuery(const std::string& t1,
                                           const std::string& t2,
                                           const std::vector<std::string>& primaryKeyList);

        int changeModifiedRows(const std::string& table,
                               const std::vector<std::string>& primaryKeyList,
                               const DbSync::ResultCallback callback);

        std::string buildSelectMatchingPKsSqlQuery(const std::string& table,
                                                   const std::vector<std::string>& primaryKeyList);

        std::string buildUpdateDataSqlQuery(const std::string& table,
                                            const std::vector<std::string>& primaryKeyList,
                                            const Row& row,
                                            const std::pair<const std::string, TableField> &field);

        std::string buildUpdatePartialDataSqlQuery(const std::string& table,
                                                   const nlohmann::json& data,
                                                   const std::vector<std::string>& primaryKeyList);

        bool getRowsToModify(const std::string& table,
                             const std::vector<std::string>& primaryKeyList,
                             std::vector<Row>& rowKeysValue);

        void updateSingleRow(const std::string& table,
                             const nlohmann::json& jsData);

        bool updateRows(const std::string& table,
                        const std::vector<std::string>& primaryKeyList,
                        const std::vector<Row>& rowKeysValue);

        void getFieldValueFromTuple(const Field& value,
                                    std::string& resultValue,
                                    const bool quotationMarks = false);

        void getFieldValueFromTuple(const Field& value,
                                    nlohmann::json& object);

        SQLiteDBEngine(const SQLiteDBEngine&) = delete;

        SQLiteDBEngine& operator=(const SQLiteDBEngine&) = delete;

        std::unique_ptr<SQLite::IStatement>const& getStatement(const std::string& sql);

        std::string getSelectAllQuery(const std::string& table, 
                                      const TableColumns& tableFields) const;

        std::string buildDeleteRelationTrigger(const nlohmann::json& data,
                                               const std::string&    baseTable);
        
        std::string buildUpdateRelationTrigger(const nlohmann::json&            data,
                                               const std::string&               baseTable,
                                               const std::vector<std::string>&  primaryKeys);

        Utils::MapWrapperSafe<std::string, TableColumns> m_tableFields;
        std::deque<std::pair<std::string, std::unique_ptr<SQLite::IStatement>>> m_statementsCache;
        const std::shared_ptr<ISQLiteFactory> m_sqliteFactory;
        std::shared_ptr<SQLite::IConnection> m_sqliteConnection;
        std::mutex m_stmtMutex;

};

#endif // _SQLITE_DBENGINE_H

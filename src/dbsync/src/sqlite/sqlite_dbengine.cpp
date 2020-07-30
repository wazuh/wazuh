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

#include <fstream>
#include "sqlite_dbengine.h"
#include "stringHelper.h"
#include "typedef.h"

SQLiteDBEngine::SQLiteDBEngine(const std::shared_ptr<ISQLiteFactory>& sqliteFactory,
                               const std::string& path,
                               const std::string& tableStmtCreation)
  : m_sqliteFactory(sqliteFactory)
{
    initialize(path, tableStmtCreation);
}

SQLiteDBEngine::~SQLiteDBEngine()
{}

void SQLiteDBEngine::setMaxRows(const std::string& table,
                                const unsigned long long maxRows)
{
    const constexpr auto ROW_COUNT_POSTFIX{"_row_count"};
    const std::string sql
    {
        maxRows ?
        "CREATE TRIGGER " + table + ROW_COUNT_POSTFIX + " BEFORE INSERT ON " + table +
        " WHEN (SELECT COUNT(*) FROM " + table + ") >= " + std::to_string(maxRows) +
        " BEGIN SELECT RAISE(FAIL, '" + SQLite::MAX_ROWS_ERROR_STRING + "'); END;"
        : "DROP TRIGGER " + table + ROW_COUNT_POSTFIX

    };
    m_sqliteConnection->execute(sql);
}

void SQLiteDBEngine::bulkInsert(const std::string& table,
                                const nlohmann::json& data)
{
    if (0 != loadTableData(table))
    {
        auto transaction { m_sqliteFactory->createTransaction(m_sqliteConnection) };
        auto const& stmt { getStatement(buildInsertBulkDataSqlQuery(table)) };
        for (const auto& jsonValue : data)
        {
            for (const auto& value : m_tableFields[table])
            {
                bindJsonData(stmt, value, jsonValue, std::get<TableHeader::CID>(value) + 1);
            }
            stmt->step();
            stmt->reset();
        }
        transaction->commit();
    }
    else
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }
}

void SQLiteDBEngine::refreshTableData(const nlohmann::json& data,
                                      const DbSync::ResultCallback callback)
{
    const std::string table { data["table"].is_string() ? data["table"].get_ref<const std::string&>() : "" };
    if (createCopyTempTable(table))
    {
        bulkInsert(table + TEMP_TABLE_SUBFIX, data["data"]);
        if (0 != loadTableData(table))
        {
            std::vector<std::string> primaryKeyList;
            if (getPrimaryKeysFromTable(table, primaryKeyList))
            {
                if (!removeNotExistsRows(table, primaryKeyList, callback))
                {
                    std::cout << "Error during the delete rows update "<< __LINE__ << " - " << __FILE__ << std::endl;
                }
                if (!changeModifiedRows(table, primaryKeyList, callback))
                {
                    std::cout << "Error during the change of modified rows " << __LINE__ << " - " << __FILE__ << std::endl;
                }
                if (!insertNewRows(table, primaryKeyList, callback))
                {
                    std::cout << "Error during the insert rows update "<< __LINE__ << " - " << __FILE__ << std::endl;
                }
            }
        }
        else
        {
            throw dbengine_error { EMPTY_TABLE_METADATA };
        }
    }
}


void SQLiteDBEngine::syncTableRowData(const std::string& table,
                                      const nlohmann::json& data,
                                      const DbSync::ResultCallback callback,
                                      const bool inTransaction)
{
    static const auto getDataToUpdate
    {
        [](const std::vector<std::string>& primaryKeyList,
           const nlohmann::json& result,
           const nlohmann::json& data,
           const bool inTransaction)
        {
            nlohmann::json ret;
            if (inTransaction)
            {
                if (result.empty())
                {
                    std::for_each(primaryKeyList.begin(),
                                  primaryKeyList.end(),
                                  [&data, &ret](const std::string& pKey)
                                  {
                                        if(data.find(pKey) != data.end())
                                        {
                                            ret[pKey] = data[pKey];
                                        }
                                  });
                }
                else
                {
                    ret = result;
                }
                ret[STATUS_FIELD_NAME] = 1;
            }
            else if (!result.empty())
            {
                ret = result;
            }
            return ret;
        }
    };
    std::vector<std::string> primaryKeyList;
    if (0 != loadTableData(table) && getPrimaryKeysFromTable(table, primaryKeyList))
    {
        ReturnTypeCallback resultCbType{ MODIFIED };
        nlohmann::json jsResult;
        const bool diffExist { getRowDiff(primaryKeyList, table, data[0], jsResult) };
        if (diffExist)
        {
            const nlohmann::json jsDataToUpdate{getDataToUpdate(primaryKeyList, jsResult, data[0], inTransaction)};
            if (!jsDataToUpdate[0].empty())
            {
                const auto& transaction { m_sqliteFactory->createTransaction(m_sqliteConnection)};
                updateSingleRow(table, jsDataToUpdate[0]);
                transaction->commit();
            }
        }
        else
        {
            resultCbType = INSERTED;
            jsResult = data;
            bulkInsert(table, data);
        }

        if (callback && !jsResult.empty())
        {
            callback(resultCbType, jsResult);
        }
    }
    else
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }
}

void SQLiteDBEngine::initializeStatusField(const nlohmann::json& tableNames) 
{
    const auto& transaction { m_sqliteFactory->createTransaction(m_sqliteConnection) };
    for (const auto& tableValue : tableNames)
    {
        const auto table { tableValue.get<std::string>() };
        if (0 != loadTableData(table)) 
        {
            const auto& fields { m_tableFields[table] };
            const auto& it { std::find_if(fields.begin(), 
                                        fields.end(),
                                        [](const ColumnData& column)
            {
                return 0 == std::get<Name>(column).compare(STATUS_FIELD_NAME);
            })};

            if (fields.end() == it)
            {
                m_tableFields[table].clear();
                auto const& stmtAdd { getStatement(std::string("ALTER TABLE " +
                                                               table +
                                                               " ADD COLUMN ") + 
                                                               STATUS_FIELD_NAME + 
                                                               " " +
                                                               STATUS_FIELD_TYPE +
                                                               " DEFAULT 1;")};
                stmtAdd->step();
            }
            auto const& stmtInit { getStatement(std::string("UPDATE " +
                                                            table +
                                                            " SET ") +
                                                            STATUS_FIELD_NAME +
                                                            "=0;")};
            stmtInit->step();
        } 
        else
        {
            throw dbengine_error { EMPTY_TABLE_METADATA };
        }
    }
    transaction->commit();
}

void SQLiteDBEngine::deleteRowsByStatusField(const nlohmann::json& tableNames) 
{
    const auto& transaction { m_sqliteFactory->createTransaction(m_sqliteConnection) };

    for (const auto& tableValue : tableNames)
    {
        const auto table { tableValue.get<std::string>() };

        if (0 != loadTableData(table)) 
        {
            auto const& stmt { getStatement(std::string("DELETE FROM " +
                                                        table +
                                                        " WHERE ") +
                                                        STATUS_FIELD_NAME +
                                                        "=0;")};
            stmt->step();
        }
        else
        {
            throw dbengine_error { EMPTY_TABLE_METADATA };
        }
    }
    transaction->commit();
}

void SQLiteDBEngine::returnRowsMarkedForDelete(const nlohmann::json& tableNames, 
                                               const DbSync::ResultCallback callback)
{
    for (const auto& tableValue : tableNames)
    {
        const auto& table { tableValue.get<std::string>() };

        if (0 != loadTableData(table)) 
        {
            const auto& tableFields { m_tableFields[table] };
            auto const& stmt { getStatement(getSelectAllQuery(table, tableFields)) };

            while (SQLITE_ROW == stmt->step())
            {
                Row registerFields;
                for(const auto& field : tableFields)
                {
                    if (!std::get<TableHeader::TXNStatusField>(field))
                    {
                        getTableData(stmt, 
                                 std::get<TableHeader::CID>(field), 
                                 std::get<TableHeader::Type>(field),
                                 std::get<TableHeader::Name>(field), 
                                 registerFields);
                    }
                }

                nlohmann::json object {};
                for (const auto& value : registerFields)
                {
                    getFieldValueFromTuple(value, object);
                }
                callback(ReturnTypeCallback::DELETED, object);
            }
        }
        else
        {
            throw dbengine_error { EMPTY_TABLE_METADATA };
        }
    }
}

void SQLiteDBEngine::selectData(const std::string& table,
                                const nlohmann::json& query,
                                const DbSync::ResultCallback& callback)
{
    if (0 != loadTableData(table))
    {
        const auto& stmt { getStatement(buildSelectQuery(table, query)) };
        const auto tableFields { m_tableFields[table] };

        while (SQLITE_ROW == stmt->step())
        {
            Row row;
            const auto& columns{ query.at("column_list") };
            // if there is a * in the column_list we need to include all data in the result.
            if (std::find_if(columns.begin(), columns.end(),[](const std::string& value){return value == "*";}) != columns.end())
            {
                for(const auto& field : tableFields)
                {
                    if (!std::get<TableHeader::TXNStatusField>(field))
                    {
                        getTableData(stmt,
                                 std::get<TableHeader::CID>(field),
                                 std::get<TableHeader::Type>(field),
                                 std::get<TableHeader::Name>(field),
                                 row);
                    }
                }
            }
            // if some specific columns are queried we have to build the result with just those rows.
            else
            {
                int32_t index{ 0l };
                for (const auto& column : columns)
                {
                    const auto& it
                    {
                        std::find_if(tableFields.begin(),
                                     tableFields.end(),
                                     [&column](const ColumnData& data)
                                     {
                                        return column == std::get<TableHeader::Name>(data);
                                     })
                    };
                    if (it != tableFields.end())
                    {
                        getTableData(stmt,
                                     index,
                                     std::get<TableHeader::Type>(*it),
                                     column,
                                     row);
                        ++index;
                    }
                }
            }
            nlohmann::json object;
            for (const auto& value : row)
            {
                getFieldValueFromTuple(value, object);
            }
            if (callback && !object.empty())
            {
                callback(SELECTED, object);
            }
        }
    }
    else
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }
}

void SQLiteDBEngine::deleteTableRowsData(const std::string& table,
                                         const nlohmann::json& data)
{
    if (0 != loadTableData(table))
    {
        const auto& stmt { getStatement(buildSelectQuery(table, query)) };
        const auto tableFields { m_tableFields[table] };

        while (SQLITE_ROW == stmt->step())
        {
            Row row;
            const auto& columns{ query.at("column_list") };
            // if there is a * in the column_list we need to include all data in the result.
            if (std::find_if(columns.begin(), columns.end(),[](const std::string& value){return value == "*";}) != columns.end())
            {
                for(const auto& field : tableFields)
                {
                    if (!std::get<TableHeader::TXNStatusField>(field))
                    {
                        getTableData(stmt,
                                 std::get<TableHeader::CID>(field),
                                 std::get<TableHeader::Type>(field),
                                 std::get<TableHeader::Name>(field),
                                 row);
                    }
                }
            }
            // if some specific columns are queried we have to build the result with just those rows.
            else
            {
                int32_t index{ 0l };
                for (const auto& column : columns)
                {
                    const auto& it
                    {
                        std::find_if(tableFields.begin(),
                                     tableFields.end(),
                                     [&column](const ColumnData& data)
                                     {
                                        return column == std::get<TableHeader::Name>(data);
                                     })
                    };
                    if (it != tableFields.end())
                    {
                        getTableData(stmt,
                                     index,
                                     std::get<TableHeader::Type>(*it),
                                     column,
                                     row);
                        ++index;
                    }
                }
            }
            nlohmann::json object;
            for (const auto& value : row)
            {
                getFieldValueFromTuple(value, object);
            }
            if (callback && !object.empty())
            {
                callback(SELECTED, object);
            }
        }
    }
    else
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }
    else
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }
}

void SQLiteDBEngine::deleteTableRowsData(const std::string& table,
                                         const nlohmann::json& data)
{
    if (0 != loadTableData(table))
    {
        std::vector<std::string> primaryKeyList;
        if (getPrimaryKeysFromTable(table, primaryKeyList))
        {
            const auto& transaction { m_sqliteFactory->createTransaction(m_sqliteConnection) };
            deleteRows(table, data, primaryKeyList);
            transaction->commit();
        }
    }
    else
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }
}


///
/// Private functions section
///

void SQLiteDBEngine::initialize(const std::string& path,
                                const std::string& tableStmtCreation)
{
    if(!path.empty())
    {
        if (cleanDB(path))
        {
            m_sqliteConnection = m_sqliteFactory->createConnection(path);
            const auto createDBQueryList { Utils::split(tableStmtCreation,';') };
            m_sqliteConnection->execute("PRAGMA temp_store = memory;");
            m_sqliteConnection->execute("PRAGMA synchronous = OFF;");
            for (const auto& query : createDBQueryList)
            {
                auto const& stmt { getStatement(query) }; 
                stmt->step();
            }
        }
    }
    
    else 
    {
        throw dbengine_error { EMPTY_DATABASE_PATH };
    }
    
}

bool SQLiteDBEngine::cleanDB(const std::string& path) 
{
    auto ret { true };
    if (path.compare(":memory") != 0)
    {
        if (std::ifstream(path))
        {
            if (0 != std::remove(path.c_str()))
            {
                ret = false;
            }
        }
    }
    return ret;
}

size_t SQLiteDBEngine::loadTableData(const std::string& table)
{
    size_t fieldsNumber { 0ull };
    if (0 == m_tableFields[table].size())
    {
        if (loadFieldData(table))
        {
            fieldsNumber = m_tableFields[table].size();
        }
    } 
    else
    {
        fieldsNumber = m_tableFields[table].size();
    }
    return fieldsNumber;    
}

std::string SQLiteDBEngine::buildInsertBulkDataSqlQuery(const std::string& table)
{
    std::string sql {"INSERT INTO "};
    sql.append(table);
    sql.append(" VALUES (");
    
    if (0 != m_tableFields[table].size())
    {
        for (size_t i = 0; i < m_tableFields[table].size();++i)
        {
            sql.append("?,");
        }
        sql = sql.substr(0, sql.size()-1);
        sql.append(");");
    }
    else
    {
        throw dbengine_error { SQL_STMT_ERROR };
    }

    return sql;
}

bool SQLiteDBEngine::loadFieldData(const std::string& table)
{
    const auto ret { !table.empty() };
    const std::string sql {"PRAGMA table_info("+table+");"}; 

    if (ret)
    {
        auto stmt { m_sqliteFactory->createStatement(m_sqliteConnection, sql) };
        while (SQLITE_ROW == stmt->step())
        {
            const auto& fieldName { stmt->column(1)->value(std::string{}) };
            m_tableFields[table].push_back(std::make_tuple(stmt->column(0)->value(int32_t{}),
                                           fieldName,
                                           columnTypeName(stmt->column(2)->value(std::string{})),
                                           1 == stmt->column(5)->value(int32_t{}),
                                           InternalColumnNames.end() != std::find(InternalColumnNames.begin(), 
                                           InternalColumnNames.end(), fieldName)));
        }
    }
    return ret;
}

ColumnType SQLiteDBEngine::columnTypeName(const std::string& type)
{
    ColumnType retVal { Unknown };
    const auto& hiddenIt {type.find(" HIDDEN")};
    const auto& it { hiddenIt == std::string::npos ? ColumnTypeNames.find(type) : ColumnTypeNames.find(type.substr(0, hiddenIt)) };
    if (ColumnTypeNames.end() != it)
    {
        retVal = it->second;
    }
    return retVal;
}

void SQLiteDBEngine::bindJsonData(std::unique_ptr<SQLite::IStatement>const& stmt, 
                                  const ColumnData& cd, 
                                  const nlohmann::json::value_type& valueType,
                                  const unsigned int cid)
{
    const auto type { std::get<TableHeader::Type>(cd) };
    const auto name { std::get<TableHeader::Name>(cd) };
    const auto& it  { valueType.find(name) };

    if (valueType.end() != it)
    {
        const auto& jsData { *it };
        if (ColumnType::BigInt == type)
        {
            int64_t value
            {   
                jsData.is_number() ? jsData.get<int64_t>() : jsData.is_string()
                && jsData.get_ref<const std::string&>().size() 
                   ? std::stoll(jsData.get_ref<const std::string&>()) 
                   : 0
            };
            stmt->bind(cid, value);
        }
        else if (ColumnType::UnsignedBigInt == type)
        {
            uint64_t value
            {
                jsData.is_number_unsigned() ? jsData.get<uint64_t>() : jsData.is_string()
                && jsData.get_ref<const std::string&>().size() 
                   ? std::stoull(jsData.get_ref<const std::string&>())
                   : 0
            };
            stmt->bind(cid, value);
        }
        else if (ColumnType::Integer == type)
        {
            auto value
            {
                jsData.is_number() ? jsData.get<int32_t>() : jsData.is_string()
                && jsData.get_ref<const std::string&>().size()
                    ? std::stol(jsData.get_ref<const std::string&>())
                    : 0
            };
            stmt->bind(cid, value);
        }
        else if (ColumnType::Text == type)
        {
            std::string value
            {
                jsData.is_string() ? jsData.get_ref<const std::string&>() : ""
            };
            stmt->bind(cid, value);
        }
        else if (ColumnType::Double == type)
        {
            double value
            {
                jsData.is_number_float() ? jsData.get<double>() : jsData.is_string()
                && jsData.get_ref<const std::string&>().size() 
                   ? std::stod(jsData.get_ref<const std::string&>()) 
                   : .0f
            };
            stmt->bind(cid, value);
        }
        else
        {
            throw dbengine_error { INVALID_COLUMN_TYPE };
        }
    }
}

bool SQLiteDBEngine::createCopyTempTable(const std::string& table)
{
    auto ret { false };
    std::string queryResult;
    deleteTempTable(table);
    if (getTableCreateQuery(table, queryResult))
    {
        if (Utils::replaceAll(queryResult, "CREATE TABLE " + table, "CREATE TEMP TABLE " + table + "_TEMP"))
        {
            auto const& stmt { getStatement(queryResult) };
            ret = SQLITE_DONE == stmt->step();
        }
    }
    return ret;
}

void SQLiteDBEngine::deleteTempTable(const std::string& table)
{ 
    try
    {
        m_sqliteConnection->execute("DROP TABLE IF EXISTS " + table + TEMP_TABLE_SUBFIX + ";");
    }
    //if the table doesn't exist we don't care.
    catch(...)
    {}
}

bool SQLiteDBEngine::getTableCreateQuery(const std::string& table,
                                         std::string& resultQuery)
{
    auto ret { false };
    const std::string sql { "SELECT sql FROM sqlite_master WHERE type='table' AND name=?;" };
    if (!table.empty())
    {
        auto const& stmt { getStatement(sql) };
        stmt->bind(1, table);
        while (SQLITE_ROW == stmt->step())
        {
            resultQuery.append(std::move(stmt->column(0)->value(std::string{})));
            resultQuery.append(";");
            ret = true;
        }
    }
    return ret;
}

bool SQLiteDBEngine::removeNotExistsRows(const std::string& table,
                                         const std::vector<std::string>& primaryKeyList,
                                         const DbSync::ResultCallback callback)
{
    auto ret { true };
    std::vector<Row> rowKeysValue;
    if (getPKListLeftOnly(table, table+TEMP_TABLE_SUBFIX, primaryKeyList, rowKeysValue))
    {
        if (deleteRows(table, primaryKeyList, rowKeysValue))
        {
            for (const auto& row : rowKeysValue)
            {
                nlohmann::json object;
                for (const auto& value : row)
                {
                    getFieldValueFromTuple(value, object);
                }
                if(callback)
                {
                    callback(ReturnTypeCallback::DELETED, object);
                }
            }
        }
        else
        {
            ret = false;
        }
    }
    return ret;
}

bool SQLiteDBEngine::getPrimaryKeysFromTable(const std::string& table,
                                             std::vector<std::string>& primaryKeyList)
{
    for(const auto& value : m_tableFields[table])
    {
        if (std::get<TableHeader::PK>(value) == true)
        {
            primaryKeyList.push_back(std::get<TableHeader::Name>(value));
        }
    }
    return m_tableFields.find(table) != m_tableFields.end();
}

void SQLiteDBEngine::getTableData(std::unique_ptr<SQLite::IStatement>const& stmt,
                                  const int32_t index,
                                  const ColumnType& type,
                                  const std::string& fieldName,
                                  Row& row)
{
    if (ColumnType::BigInt == type)
    {
        row[fieldName] = std::make_tuple(type,std::string(),0,stmt->column(index)->value(int64_t{}),0,0);
    }
    else if (ColumnType::UnsignedBigInt == type)
    {
        row[fieldName] = std::make_tuple(type,std::string(),0,0,stmt->column(index)->value(int64_t{}),0);
    }
    else if (ColumnType::Integer == type)
    {
        row[fieldName] = std::make_tuple(type,std::string(),stmt->column(index)->value(int32_t{}),0,0,0);
    }
    else if (ColumnType::Text == type)
    {
        row[fieldName] = std::make_tuple(type,stmt->column(index)->value(std::string{}),0,0,0,0);
    }
    else if (ColumnType::Double == type)
    {
        row[fieldName] = std::make_tuple(type,std::string(),0,0,0,stmt->column(index)->value(double{}));
    }
    else
    {
        throw dbengine_error { INVALID_COLUMN_TYPE };
    }
}

bool SQLiteDBEngine::getLeftOnly(const std::string& t1,
                                 const std::string& t2,
                                 const std::vector<std::string>& primaryKeyList,
                                 std::vector<Row>& returnRows)
{
    auto ret { false };
    const std::string query { buildLeftOnlyQuery(t1, t2, primaryKeyList) };
    if (!t1.empty() && !query.empty())
    {
        auto const& stmt { getStatement(query) };
        const auto tableFields { m_tableFields[t1] };
        while (SQLITE_ROW == stmt->step()) 
        {
            Row registerFields;
            for(const auto& field : tableFields)
            {
                getTableData(stmt, 
                             std::get<TableHeader::CID>(field), 
                             std::get<TableHeader::Type>(field),
                             std::get<TableHeader::Name>(field), 
                             registerFields);
            }
            returnRows.push_back(std::move(registerFields));
        }
        ret = true;
    } 
    return ret;
}

bool SQLiteDBEngine::getPKListLeftOnly(const std::string& t1,
                                       const std::string& t2,
                                       const std::vector<std::string>& primaryKeyList,
                                       std::vector<Row>& returnRows)
{
    auto ret { false };
    const std::string sql { buildLeftOnlyQuery(t1, t2, primaryKeyList, true) };
    if (!t1.empty() && !sql.empty())
    {
        auto const& stmt { getStatement(sql) };
        const auto tableFields { m_tableFields[t1] };
        while (SQLITE_ROW == stmt->step()) 
        {
            Row registerFields;
            for(const auto& pkValue : primaryKeyList)
            {
                auto index { 0ull };
                const auto& it
                {
                    std::find_if(tableFields.begin(), tableFields.end(), 
                                [&pkValue](const ColumnData& columnData)
                                    {
                                        return std::get<TableHeader::Name>(columnData) == pkValue;
                                    })
                };

                if (tableFields.end() != it)
                { 
                    getTableData(stmt, 
                                 index,
                                 std::get<TableHeader::Type>(*it),
                                 std::get<TableHeader::Name>(*it), 
                                 registerFields);
                }
                ++index;
            }
            returnRows.push_back(std::move(registerFields));
        }
        ret = true;
    } 
    return ret;
}

std::string SQLiteDBEngine::buildDeleteBulkDataSqlQuery(const std::string& table,
                                                        const std::vector<std::string>& primaryKeyList)
{
    std::string sql{ "DELETE FROM " };
    sql.append(table);
    sql.append(" WHERE ");
    if (0 != primaryKeyList.size())
    {
        for (const auto& value : primaryKeyList)
        {
            sql.append(value);
            sql.append("=? AND ");
        }
        sql = sql.substr(0, sql.size()-5);
        sql.append(";");
    }
    else
    {
        throw dbengine_error { SQL_STMT_ERROR };
    }
    return sql;
}

bool SQLiteDBEngine::deleteRows(const std::string& table,
                                const std::vector<std::string>& primaryKeyList,
                                const std::vector<Row>& rowsToRemove)
{
    auto ret { false };
    const auto sql { buildDeleteBulkDataSqlQuery(table, primaryKeyList) };

    if(!sql.empty())
    {
        auto transaction { m_sqliteFactory->createTransaction(m_sqliteConnection)};
        auto const& stmt { getStatement(sql) };

        for (const auto& row : rowsToRemove)
        {
            auto index {1l};
            for (const auto& value : primaryKeyList)
            {
                bindFieldData(stmt, index, row.at(value));
                ++index;
            }
            stmt->step();
            stmt->reset();
        }
        transaction->commit();
        ret = true;
    }
    else
    {
        throw dbengine_error { SQL_STMT_ERROR };
    }
    return ret;
}

void SQLiteDBEngine::deleteRows(const std::string& table,
                                const nlohmann::json& data,
                                const std::vector<std::string>& primaryKeyList)
{
    const auto& tableFields { m_tableFields[table] };
    const auto& stmt
    {
        getStatement(buildDeleteBulkDataSqlQuery(table, primaryKeyList))
    };

    for (const auto& jsRow : data)
    {
        int32_t index { 1l };
        for (const auto& pkValue : primaryKeyList)
        {
            const auto& it
            {
                std::find_if(tableFields.begin(), tableFields.end(),
                                [&pkValue](const ColumnData& column)
                                {
                                    return 0 == std::get<Name>(column).compare(pkValue);
                                })
            };

            if(it != tableFields.end())
            {
                bindJsonData(stmt, *it, jsRow, index);
                ++index;
            }
        }
        stmt->step();
        stmt->reset();
    }
}

void SQLiteDBEngine::bindFieldData(const std::unique_ptr<SQLite::IStatement>& stmt,
                                   const int32_t index,
                                   const TableField& fieldData)
{
    const auto type { std::get<GenericTupleIndex::GenType>(fieldData) };
    if (ColumnType::BigInt == type)
    {
        const auto value { std::get<GenericTupleIndex::GenBigInt>(fieldData) };
        stmt->bind(index, value);
    }
    else if (ColumnType::UnsignedBigInt == type)
    {
        const auto value { std::get<GenericTupleIndex::GenUnsignedBigInt>(fieldData) };
        stmt->bind(index, value);
    }
    else if (ColumnType::Integer == type)
    {
        const auto value { std::get<GenericTupleIndex::GenInteger>(fieldData) };
        stmt->bind(index, value);
    }
    else if (ColumnType::Text == type)
    {
        const auto value { std::get<GenericTupleIndex::GenString>(fieldData) };
        stmt->bind(index, value);
    }
    else if (ColumnType::Double == type)
    {
        const auto value { std::get<GenericTupleIndex::GenDouble>(fieldData) };
        stmt->bind(index, value);
    }
    else
    {
        throw dbengine_error { INVALID_DATA_BIND };
    }
}


std::string SQLiteDBEngine::buildSelectQuery(const std::string& table,
                                             const nlohmann::json& jsQuery)
{
    const auto& columns{ jsQuery.at("column_list")};
    const auto& itFilter{ jsQuery.find("row_filter")};
    /*optional fields*/
    const auto& itDistinct{ jsQuery.find("distinct_opt") };
    const auto& itOrderBy{ jsQuery.find("order_by_opt") };
    const auto& itCount{ jsQuery.find("count_opt") };

    std::string sql{ "SELECT "};
    if (itDistinct != jsQuery.end() && itDistinct->get<bool>())
    {
        sql += "DISTINCT ";
    }
    for (const auto& column : columns)
    {
        sql += column;
        sql += ",";
    }
    sql = sql.substr(0, sql.size()-1);

    sql += " FROM " + table;
    if (itFilter != jsQuery.end() && !itFilter->get<std::string>().empty())
    {
        sql += " WHERE ";
        sql += itFilter->get<std::string>();
    }
    if (itOrderBy != jsQuery.end() && !itOrderBy->get<std::string>().empty())
    {
        sql += " ORDER BY " + itOrderBy->get<std::string>();
    }
    if (itCount != jsQuery.end())
    {
        const unsigned int limit{*itCount};
        sql += " LIMIT " + std::to_string(limit);
    }
    sql += ";";
    return sql;
}

std::string SQLiteDBEngine::buildLeftOnlyQuery(const std::string& t1,
                                               const std::string& t2,
                                               const std::vector<std::string>& primaryKeyList,
                                               const bool returnOnlyPKFields)
{  
    std::string fieldsList;
    std::string onMatchList;
    std::string nullFilterList;
  
    for (const auto& value : primaryKeyList)
    {
        if (returnOnlyPKFields)
        {
            fieldsList.append("t1."+value+",");
        }
        onMatchList.append("t1." + value + "= t2." + value + " AND ");
        nullFilterList.append("t2."+value+ " IS NULL AND ");
    }

    if (returnOnlyPKFields)
    {
        fieldsList = fieldsList.substr(0, fieldsList.size()-1);
    }
    else
    {
        fieldsList.append("*");
    }
    onMatchList = onMatchList.substr(0, onMatchList.size()-5);
    nullFilterList = nullFilterList.substr(0, nullFilterList.size()-5);

    return std::string("SELECT "+fieldsList+" FROM "+t1+" t1 LEFT JOIN "+t2+" t2 ON "+onMatchList+" WHERE "+nullFilterList+";");
} 

bool SQLiteDBEngine::getRowDiff(const std::vector<std::string>& primaryKeyList,
                                const std::string& table,
                                const nlohmann::json& data,
                                nlohmann::json& jsResult)
{
    bool diffExist { false };
    bool isModified { false };
    const auto& stmt
    {
        getStatement(buildSelectMatchingPKsSqlQuery(table, primaryKeyList))
    };

    const auto& tableFields { m_tableFields[table] };
    int32_t index { 1l };
    for (const auto& pkValue : primaryKeyList)
    {
        const auto& it
        {
            std::find_if(tableFields.begin(), tableFields.end(),
                            [&pkValue](const ColumnData& column)
                            {
                                return 0 == std::get<Name>(column).compare(pkValue);
                            })
        };

        if(it != tableFields.end())
        {
            jsResult[pkValue] = data[pkValue];
            bindJsonData(stmt, *it, data, index);
            ++index;
        }
    }

    diffExist = SQLITE_ROW == stmt->step();
    if (diffExist)
    {
        // The row exist, so lets generate the diff
        Row registryFields;
        for(const auto& field : tableFields)
        {
            getTableData(stmt,
                        std::get<TableHeader::CID>(field),
                        std::get<TableHeader::Type>(field),
                        std::get<TableHeader::Name>(field),
                        registryFields);
        }

        if(!registryFields.empty())
        {
            for (const auto& value : registryFields)
            {
                nlohmann::json object;
                getFieldValueFromTuple(value, object);
                const auto& it
                {
                    data.find(value.first)
                };
                if (data.end() != it)
                {
                    if(*it != object[value.first])
                    {
                        // Diff found
                        isModified = true;
                        jsResult[value.first] = *it;
                    }
                }
            }
        }
    }
    if(!isModified)
    {
        jsResult.clear();
    }
    return diffExist;
}

bool SQLiteDBEngine::insertNewRows(const std::string& table,
                                   const std::vector<std::string>& primaryKeyList,
                                   const DbSync::ResultCallback callback)
{
    auto ret { true };
    std::vector<Row> rowValues;
    if (getLeftOnly(table+TEMP_TABLE_SUBFIX, table, primaryKeyList, rowValues))
    {
        bulkInsert(table, rowValues);
        for (const auto& row : rowValues)
        {
            nlohmann::json object;
            for (const auto& value : row)
            {
                getFieldValueFromTuple(value, object);
            }
            if(callback)
            {
                callback(ReturnTypeCallback::INSERTED, object);
            }
        }
    }
    return ret;
}

void SQLiteDBEngine::bulkInsert(const std::string& table,
                                const std::vector<Row>& data)
{
    auto transaction { m_sqliteFactory->createTransaction(m_sqliteConnection)};
    auto const& stmt { getStatement(buildInsertBulkDataSqlQuery(table)) };

    for (const auto& row : data)
    {
        for (const auto& value : m_tableFields[table])
        {
            auto it { row.find(std::get<TableHeader::Name>(value))};
            if (row.end() != it)
            {
                bindFieldData(stmt, std::get<TableHeader::CID>(value) + 1, (*it).second);
            }
        }
        stmt->step();
        stmt->reset();
    }
    transaction->commit();
}

int SQLiteDBEngine::changeModifiedRows(const std::string& table, 
                                       const std::vector<std::string>& primaryKeyList, 
                                       const DbSync::ResultCallback callback)
{
    auto ret { true };
    std::vector<Row> rowKeysValue;
    if (getRowsToModify(table, primaryKeyList, rowKeysValue))
    {
        if (updateRows(table, primaryKeyList, rowKeysValue))
        {
            for (const auto& row : rowKeysValue)
            {
                nlohmann::json object;
                for (const auto& value : row)
                {
                    getFieldValueFromTuple(value, object);
                }
                if(callback)
                {
                    callback(ReturnTypeCallback::MODIFIED, object);
                }
            }
        }
        else
        {
            ret = false;
        }
    }
    return ret;
}

std::string SQLiteDBEngine::buildUpdatePartialDataSqlQuery(const std::string& table,
                                                           const nlohmann::json& data,
                                                           const std::vector<std::string>& primaryKeyList)
                  
{
    std::string sql{ "UPDATE " + table + " SET "};
    if (0 != primaryKeyList.size())
    {
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            if (std::find(primaryKeyList.begin(), primaryKeyList.end(), it.key()) == primaryKeyList.end())
            {
                sql += it.key() + "=?,";
            }
        }
        sql = sql.substr(0, sql.size()-1);  // Remove the last " , "
        sql.append(" WHERE ");
        for (const auto& value : primaryKeyList)
        {
            sql.append(value);
            sql.append("=? AND ");
        }
        sql = sql.substr(0, sql.size()-5);  // Remove the last " AND "
        sql.append(";");
    }
    else
    {
        throw dbengine_error{ SQL_STMT_ERROR };
    }
    return sql;
}

std::string SQLiteDBEngine::buildSelectMatchingPKsSqlQuery(const std::string& table,
                                                           const std::vector<std::string>& primaryKeyList)
                  
{
    std::string sql{ "SELECT * FROM " };
    sql.append(table);
    sql.append(" WHERE ");
    if (0 != primaryKeyList.size())
    {
        for (const auto& value : primaryKeyList)
        {
            sql.append(value);
            sql.append("=? AND ");
        }
        sql = sql.substr(0, sql.size()-5);  // Remove the last " AND "
        sql.append(";");
    }
    else
    {
        throw dbengine_error{ SQL_STMT_ERROR };
    }
    return sql;
}

std::string SQLiteDBEngine::buildUpdateDataSqlQuery(const std::string& table, 
                                                    const std::vector<std::string>& primaryKeyList,
                                                    const Row& row,
                                                    const std::pair<const std::string, TableField> &field)
{
    std::string sql{ "UPDATE " };
    sql.append(table);
    sql.append(" SET ");
    sql.append(field.first);
    sql.append("=");
    getFieldValueFromTuple(field, sql, true);
    sql.append(" WHERE ");
    if (0 != primaryKeyList.size())
    {
        for (const auto& value : primaryKeyList)
        {
            const auto it { row.find("PK_"+value) };
            if (it != row.end())
            {
                sql.append(value);
                sql.append("=");  
                getFieldValueFromTuple((*it), sql, true);
            }
            else
            {
                sql.clear();
                break;
            }
            sql.append(" AND ");
        }
        sql = sql.substr(0, sql.length()-5);
        if (sql.length() > 0)
        {
            sql.append(";");
        }
    }
    else
    {
        throw dbengine_error{ SQL_STMT_ERROR };
    }
    return sql;
}

std::string SQLiteDBEngine::buildModifiedRowsQuery(const std::string& t1,
                                                   const std::string& t2,
                                                   const std::vector<std::string>& primaryKeyList)
{
    std::string fieldsList;
    std::string onMatchList;

    for (const auto& value : primaryKeyList)
    {
        fieldsList.append("t1."+value+",");
        onMatchList.append("t1." + value + "=t2." + value + " AND ");
    }

    for (const auto& value : m_tableFields[t1])
    {
        const auto fieldName {std::get<TableHeader::Name>(value)};
        fieldsList.append("CASE WHEN t1.");
        fieldsList.append(fieldName);
        fieldsList.append("<>t2.");
        fieldsList.append(fieldName);
        fieldsList.append(" THEN t1.");
        fieldsList.append(fieldName);
        fieldsList.append(" ELSE NULL END AS DIF_");
        fieldsList.append(fieldName);
        fieldsList.append(",");
    }

    fieldsList  = fieldsList.substr(0, fieldsList.size()-1);
    onMatchList = onMatchList.substr(0, onMatchList.size()-5);
    std::string ret {"SELECT "};
    ret.append(fieldsList);
    ret.append(" FROM (select *,'");
    ret.append(t1);
    ret.append("' as val from ");
    ret.append(t1);
    ret.append(" UNION ALL select *,'");
    ret.append(t2);
    ret.append("' as val from ");
    ret.append(t2);
    ret.append(") t1 INNER JOIN ");
    ret.append(t1);
    ret.append(" t2 ON ");
    ret.append(onMatchList);
    ret.append(" WHERE t1.val = '");
    ret.append(t2);
    ret.append("';");
    
    return ret;
} 

bool SQLiteDBEngine::getRowsToModify(const std::string& table,
                                     const std::vector<std::string>& primaryKeyList,
                                     std::vector<Row>& rowKeysValue)
{
    auto ret { false };
    auto sql { buildModifiedRowsQuery(table, table+TEMP_TABLE_SUBFIX, primaryKeyList) };

    if(!sql.empty())
    {
        auto const& stmt { getStatement(sql) };

        while (SQLITE_ROW == stmt->step())
        {
            const auto tableFields { m_tableFields[table] };
            Row registerFields;
            int32_t index {0l};
            for(const auto& pkValue : primaryKeyList)
            {
                const auto it
                {
                    std::find_if(tableFields.begin(), tableFields.end(), 
                                [&pkValue] (const ColumnData& cd)
                                {
                                    return std::get<TableHeader::Name>(cd).compare(pkValue) == 0;
                                })
                };
                if (tableFields.end() != it)
                {
                    getTableData(stmt,
                                 index,
                                 std::get<TableHeader::Type>(*it),
                                 "PK_" + std::get<TableHeader::Name>(*it),
                                 registerFields);
                }
                ++index;
            }
            for(const auto& field : tableFields)
            {
                if (registerFields.end() == registerFields.find(std::get<TableHeader::Name>(field)))
                {
                    if (stmt->column(index)->hasValue())
                    {
                        getTableData(stmt, index, std::get<TableHeader::Type>(field), 
                                     std::get<TableHeader::Name>(field), registerFields);
                    }
                }
                ++index;
            }
            rowKeysValue.push_back(std::move(registerFields));
        }
        ret = true;
    }
    else
    {
        throw dbengine_error { SQL_STMT_ERROR };
    }

    return ret;
}

void SQLiteDBEngine::updateSingleRow(const std::string& table,
                                     const nlohmann::json& jsData)
{
    std::vector<std::string> primaryKeyList;
    if (getPrimaryKeysFromTable(table, primaryKeyList))
    {
        const auto& stmt { getStatement(buildUpdatePartialDataSqlQuery(table, jsData, primaryKeyList)) };
        auto tableFields { m_tableFields[table] };
        int32_t index { 1l };
        std::sort(tableFields.begin(),
                  tableFields.end(),
                  [](const ColumnData& data1, const ColumnData& data2)
                  {
                    const auto pk1{std::get<TableHeader::PK>(data1)};
                    const auto pk2{std::get<TableHeader::PK>(data2)};
                    if (pk1 != pk2)
                    {
                        return !pk1;
                    }
                    const auto name1{std::get<TableHeader::Name>(data1)};
                    const auto name2{std::get<TableHeader::Name>(data2)};
                    return name1 < name2;
                  });
        for (const auto& field : tableFields)
        {
            if (jsData.end() != jsData.find(std::get<TableHeader::Name>(field)))
            {
                bindJsonData(stmt, field, jsData, index);
                ++index;
            }
        }
        stmt->step();
        stmt->reset();
    }
}

bool SQLiteDBEngine::updateRows(const std::string& table,
                                const std::vector<std::string>& primaryKeyList,
                                const std::vector<Row>& rowKeysValue)
{
    auto transaction { m_sqliteFactory->createTransaction(m_sqliteConnection)};
    
    for (const auto& row : rowKeysValue)
    {
        for (const auto& field : row)
        {
            if (0 != field.first.substr(0,3).compare("PK_"))
            {
                const auto sql 
                { 
                    buildUpdateDataSqlQuery(table, 
                                            primaryKeyList,
                                            row,
                                            field) 
                };
                m_sqliteConnection->execute(sql);
            }
        }
    }
    transaction->commit();
    return true;
}

void SQLiteDBEngine::getFieldValueFromTuple(const Field& value,
                                            nlohmann::json& object)
{
    const auto rowType { std::get<GenericTupleIndex::GenType>(value.second) };
    if (ColumnType::BigInt == rowType)
    {
        object[value.first] = std::get<ColumnType::BigInt>(value.second);
    }
    else if (ColumnType::UnsignedBigInt == rowType)
    {
        object[value.first] = std::get<ColumnType::UnsignedBigInt>(value.second);
    }
    else if (ColumnType::Integer == rowType)
    {
        object[value.first] = std::get<ColumnType::Integer>(value.second);
    }
    else if (ColumnType::Text == rowType)
    {
        object[value.first] = std::get<ColumnType::Text>(value.second);
    }
    else if (ColumnType::Double == rowType)
    {
        object[value.first] = std::get<ColumnType::Double>(value.second);
    }
    else
    {
        throw dbengine_error { DATATYPE_NOT_IMPLEMENTED };
    }
}

void SQLiteDBEngine::getFieldValueFromTuple(const Field& value,
                                            std::string& resultValue,
                                            const bool quotationMarks)
{
    const auto rowType { std::get<GenericTupleIndex::GenType>(value.second) };
    if (ColumnType::BigInt == rowType)
    {
        resultValue.append(std::to_string(std::get<ColumnType::BigInt>(value.second)));
    }
    else if (ColumnType::UnsignedBigInt == rowType)
    {
        resultValue.append(std::to_string(std::get<ColumnType::UnsignedBigInt>(value.second)));
    }
    else if (ColumnType::Integer == rowType)
    {
        resultValue.append(std::to_string(std::get<ColumnType::Integer>(value.second)));
    }
    else if (ColumnType::Text == rowType)
    {
        if(quotationMarks)
        {
            resultValue.append("'"+std::get<ColumnType::Text>(value.second)+"'");
        }
        else
        {
            resultValue.append(std::get<ColumnType::Text>(value.second));
        }
    }
    else if (ColumnType::Double == rowType)
    {
        resultValue.append(std::to_string(std::get<ColumnType::Double>(value.second)));
    }
    else
    {
        throw dbengine_error { DATATYPE_NOT_IMPLEMENTED };
    }
}

std::unique_ptr<SQLite::IStatement>const& SQLiteDBEngine::getStatement(const std::string& sql) 
{
    const auto it { m_statementsCache.find(sql) };
    if(m_statementsCache.end() != it) 
    {
        it->second->reset();
        return it->second;
    } 
    else 
    {
        m_statementsCache[sql] = m_sqliteFactory->createStatement(m_sqliteConnection, sql);
        return m_statementsCache[sql];
    }
}

std::string SQLiteDBEngine::getSelectAllQuery(const std::string& table, 
                                              const TableColumns& tableFields) const
{
    std::string retVal { "SELECT " };

    if (!tableFields.empty() && !table.empty())
    {
        for(const auto& field : tableFields)
        {
            if (!std::get<TableHeader::TXNStatusField>(field))
            {
                retVal.append(std::get<TableHeader::Name>(field));
                retVal.append(",");
            }

        }
        retVal = retVal.substr(0, retVal.size()-1);
        retVal.append(" FROM ");
        retVal.append(table);
        retVal.append(" WHERE ");
        retVal.append(STATUS_FIELD_NAME);
        retVal.append("=0;");
    }
    else 
    {
        throw dbengine_error { EMPTY_TABLE_METADATA };
    }

    return retVal;
} 
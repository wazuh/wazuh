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

#include "sqlite_dbengine.h"
#include "stringHelper.h"
#include "typedef.h"
#include <fstream>

SQLiteDBEngine::SQLiteDBEngine(std::shared_ptr<ISQLiteFactory> sqliteFactory,
                               const std::string& path,
                               const std::string& tableStmtCreation)
  : m_sqliteFactory(sqliteFactory)
{
    initialize(path, tableStmtCreation);
}

SQLiteDBEngine::~SQLiteDBEngine()
{}

void SQLiteDBEngine::execute(const std::string& /*query*/)
{}

void SQLiteDBEngine::select(const std::string& /*query*/,
                            nlohmann::json& /*result*/)
{}

void SQLiteDBEngine::bulkInsert(const std::string& table,
                                const nlohmann::json& data)
{
    if (0 != loadTableData(table))
    {
        const auto sql { buildInsertBulkDataSqlQuery(table) };
        if(!sql.empty())
        {
            auto transaction { m_sqliteFactory->createTransaction(m_sqliteConnection) };
            auto const& stmt { getStatement(sql) };
            for (const auto& jsonValue : data)
            {
                for (const auto& value : m_tableFields[table])
                {
                    bindJsonData(stmt, value, jsonValue);
                }
                stmt->step();
                stmt->reset();
            }
            transaction->commit();
        }
    }
}

void SQLiteDBEngine::refreshTableData(const nlohmann::json& data,
                                      const std::tuple<nlohmann::json&, void *> delta)
{
    const std::string table { data["table"].is_string() ? data["table"].get_ref<const std::string&>() : "" };
    if (createCopyTempTable(table))
    {
        bulkInsert(table + kTempTableSubFix, data["data"]);
        if (0 != loadTableData(table))
        {
            std::vector<std::string> primaryKeyList;
            if (getPrimaryKeysFromTable(table, primaryKeyList))
            {
                if (!removeNotExistsRows(table, primaryKeyList, delta))
                {
                    std::cout << "Error during the delete rows update "<< __LINE__ << " - " << __FILE__ << std::endl;
                }
                if (!changeModifiedRows(table, primaryKeyList, delta))
                {
                    std::cout << "Error during the change of modified rows " << __LINE__ << " - " << __FILE__ << std::endl;
                }
                if (!insertNewRows(table, primaryKeyList, delta))
                {
                    std::cout << "Error during the insert rows update "<< __LINE__ << " - " << __FILE__ << std::endl;
                }
            }
        }
    }
}

bool SQLiteDBEngine::getPKFromTable(const std::string& table)
{
    auto ret { false };
    const std::string table { data["table"].is_string() ? data["table"].get_ref<const std::string&>() : "" };



    std::get<TableHeader::PK>(value) == true

    for (const auto& jsonValue : data)
    {
    }
}

void SQLiteDBEngine::syncTableRowData(const std::string& table,
                                      const nlohmann::json& data,
                                      std::tuple<nlohmann::json&, void *> delta)
{
    // 1) SELECT de "data" en "table"
    // 2) 
    if (0 != loadTableData(table))
    {
        std::string oldValue;
        // get PK from data -> dataPK
        const auto pKey { getPKFromTable(table) };
        if(getValueFromTable(table, data[pkey], pKey, oldValue))
        {
            // modification
            delta -> modify
        }
        else
        {
            // insertion
            delta -> insert
        }
        bulkInsert();
    }
}


///
/// Private functions section
///

void SQLiteDBEngine::initialize(const std::string& path,
                                const std::string& tableStmtCreation)
{
    if (cleanDB(path))
    {
        m_sqliteConnection = m_sqliteFactory->createConnection(path);
        const auto create_db_querys_list { Utils::split(tableStmtCreation,';') };
        m_sqliteConnection->execute("PRAGMA temp_store = memory;");
        m_sqliteConnection->execute("PRAGMA synchronous = OFF;");
        for (const auto& query : create_db_querys_list)
        {
            auto const& stmt { getStatement(query) }; 
            stmt->step();
        }
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
        sql.clear();
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
            m_tableFields[table].push_back(std::make_tuple(
            stmt->column(0)->value(int32_t{}),
            stmt->column(1)->value(std::string{}),
            columnTypeName(stmt->column(2)->value(std::string{})),
            1 == stmt->column(5)->value(int32_t{})));
        }
    }
    return ret;
}

ColumnType SQLiteDBEngine::columnTypeName(const std::string& type)
{
    for (const auto& col : kColumnTypeNames)
    {
        if (col.second == type)
        {
            return col.first;
        }
    }
    return Unknown;
}

void SQLiteDBEngine::bindJsonData(std::unique_ptr<SQLite::IStatement>const& stmt, 
                                  const ColumnData& cd, 
                                  const nlohmann::json::value_type& valueType)
{
    const auto type { std::get<TableHeader::Type>(cd) };
    const auto cid  { std::get<TableHeader::CID>(cd) + 1 };
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
        else if (ColumnType::Blob == type)
        {
            std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
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
        m_sqliteConnection->execute("DROP TABLE " + table + kTempTableSubFix + ";");
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
                                         const std::tuple<nlohmann::json&, void *> delta)
{
    auto ret { true };
    std::vector<Row> rowKeysValue;
    if (getPKListLeftOnly(table, table+kTempTableSubFix, primaryKeyList, rowKeysValue))
    {
        if (deleteRows(table, primaryKeyList, rowKeysValue))
        {
            for (const auto& row : rowKeysValue)
            {
                nlohmann::json object;
                for (const auto& value : row)
                {
                    if(!getFieldValueFromTuple(value, object))
                    {
                        std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
                    }
                }
                auto callback { std::get<ResponseType::RTCallback>(delta) };
                if (nullptr != callback)
                {
                    result_callback_t Notify = reinterpret_cast<result_callback_t>(callback);
                    cJSON* json_result { cJSON_Parse(object.dump().c_str()) };
                    Notify(ReturnTypeCallback::DELETED, json_result);
                    cJSON_Delete(json_result);
                }
                else
                {
                    std::get<ResponseType::RTJson>(delta)["deleted"].push_back(std::move(object));
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

template<typename T>
bool SQLiteDBEngine::getValueFromTable(const std::string& table,
                                       const std::string& primaryKey,
                                       const T& keyValue, 
                                       std::string& resultQuery)
{
    auto ret { false };
    const std::string sqlStmtString { "SELECT "+primaryKey+" FROM "+table+" WHERE "+primaryKey+" ='?';" };
    if (!table.empty())
    {
        auto const& sqlStmt { getStatement(sqlStmtString) };
        sqlStmt->bind(1, keyValue);
        while (SQLITE_ROW == stmt->step())
        {
            resultQuery.append(std::move(stmt->column(0)->value(std::string{})));
            resultQuery.append(";");
            ret = true;
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

int32_t SQLiteDBEngine::getTableData(std::unique_ptr<SQLite::IStatement>const & stmt,
                                     const int32_t index,
                                     const ColumnType& type,
                                     const std::string& fieldName,
                                     Row& row)
{
    int32_t rc { SQLITE_OK };
 
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
    else if (ColumnType::Blob == type)
    {
        std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
    }
    else
    {
        rc = SQLITE_ERROR;
    }
    return rc;
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
        sql.clear();
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
                if (!bindFieldData(stmt, index, row.at(value)))
                {
                    std::cout << "bind error: " <<  index << std::endl;
                }
                ++index;
            }
            stmt->step();
            stmt->reset();
        }
        transaction->commit();
        ret = true;
    }
    return ret;
}

int32_t SQLiteDBEngine::bindFieldData(std::unique_ptr<SQLite::IStatement>const & stmt,
                                      const int32_t index,
                                      const TableField& fieldData)
{
    int32_t rc { SQLITE_ERROR };
    const auto type = std::get<GenericTupleIndex::GenType>(fieldData);
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

    }else if (ColumnType::Blob == type)
    {
        std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
    }

    return rc;
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

bool SQLiteDBEngine::syncNewRows(const std::string& table,
                                 const std::vector<std::string>& primaryKeyList,
                                 const std::tuple<nlohmann::json&, void *> delta)
{
    auto ret { true };
    std::vector<Row> rowValues;
    if (getLeftOnly(table+kTempTableSubFix, table, primaryKeyList, rowValues))
    {
        bulkInsert(table, rowValues);
        for (const auto& row : rowValues)
        {
            nlohmann::json object;
            for (const auto& value : row)
            {
                if(!getFieldValueFromTuple(value, object))
                {
                    std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
                }
            }
            auto callback { std::get<ResponseType::RTCallback>(delta) };
            if (nullptr != callback)
            {
                result_callback_t Notify = reinterpret_cast<result_callback_t>(callback);
                cJSON* jsResult { cJSON_Parse(object.dump().c_str()) };
                Notify(ReturnTypeCallback::INSERTED, jsResult);
                cJSON_Delete(jsResult);
            }
            else
            {
                std::get<ResponseType::RTJson>(delta)["inserted"].push_back(std::move(object));
            }
        }
    }
    return ret;
}

bool SQLiteDBEngine::insertNewRows(const std::string& table,
                                   const std::vector<std::string>& primaryKeyList,
                                   const std::tuple<nlohmann::json&, void *> delta)
{
    auto ret { true };
    std::vector<Row> rowValues;
    if (getLeftOnly(table+kTempTableSubFix, table, primaryKeyList, rowValues))
    {
        bulkInsert(table, rowValues);
        for (const auto& row : rowValues)
        {
            nlohmann::json object;
            for (const auto& value : row)
            {
                if(!getFieldValueFromTuple(value, object))
                {
                    std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
                }
            }
            auto callback { std::get<ResponseType::RTCallback>(delta) };
            if (nullptr != callback)
            {
                result_callback_t Notify = reinterpret_cast<result_callback_t>(callback);
                cJSON* jsResult { cJSON_Parse(object.dump().c_str()) };
                Notify(ReturnTypeCallback::INSERTED, jsResult);
                cJSON_Delete(jsResult);
            }
            else
            {
                std::get<ResponseType::RTJson>(delta)["inserted"].push_back(std::move(object));
            }
        }
    }
    return ret;
}

void SQLiteDBEngine::bulkInsert(const std::string& table,
                                const std::vector<Row>& data)
{
    const auto sql { buildInsertBulkDataSqlQuery(table) };
    if(!sql.empty())
    {
        auto transaction { m_sqliteFactory->createTransaction(m_sqliteConnection)};
        auto const& stmt { getStatement(sql) };

        for (const auto& row : data)
        {
            for (const auto& value : m_tableFields[table])
            {
                auto it { row.find(std::get<TableHeader::Name>(value))};
                if (row.end() != it)
                {
                    if (!bindFieldData(stmt, std::get<TableHeader::CID>(value) + 1, (*it).second ))
                    {
                        std::cout << "bind error: " <<  std::get<TableHeader::CID>(value) << std::endl;
                    }
                }
            }
            stmt->step();
            stmt->reset();
        }
        transaction->commit();
    }
}

int SQLiteDBEngine::changeModifiedRows(const std::string& table, 
                                       const std::vector<std::string>& primaryKeyList, 
                                       const std::tuple<nlohmann::json&, void *> delta)
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
                    if(!getFieldValueFromTuple(value, object))
                    {
                        std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
                    }
                }
                auto callback { std::get<ResponseType::RTCallback>(delta) };
                if (nullptr != callback)
                {
                    result_callback_t Notify = reinterpret_cast<result_callback_t>(callback);
                    cJSON* jsResul { cJSON_Parse(object.dump().c_str()) };
                    Notify(ReturnTypeCallback::MODIFIED, jsResul);
                    cJSON_Delete(jsResul);
                }
                else
                {
                    std::get<ResponseType::RTJson>(delta)["modified"].push_back(std::move(object));
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

std::string SQLiteDBEngine::buildUpdateDataSqlQuery(const std::string& table, 
                                                    const std::vector<std::string>& primaryKeyList,
                                                    const Row& row,
                                                    const std::pair<const std::__cxx11::string, TableField> &field)
{
    std::string sql{ "UPDATE " };
    sql.append(table);
    sql.append(" SET ");
    sql.append(field.first);
    sql.append("=");
    if (getFieldValueFromTuple(field, sql, true))
    {
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
                    if (!getFieldValueFromTuple((*it), sql, true))
                    {
                        sql.clear();
                        break;
                    }
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
            sql.clear();
        }
    }
    else
    {
        sql.clear();
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
    auto sql { buildModifiedRowsQuery(table, table+kTempTableSubFix, primaryKeyList) };

    if(!sql.empty())
    {
        auto const& stmt { getStatement(sql) };

        while (SQLITE_ROW == stmt->step())
        {
            const auto tableFields { m_tableFields[table] };
            Row registerFields;
            int32_t index {0l};
            for(const auto& pk_value : primaryKeyList)
            {
                const auto it
                {
                    std::find_if(tableFields.begin(), tableFields.end(), 
                                [&pk_value] (const ColumnData& cd)
                                {
                                    return std::get<TableHeader::Name>(cd).compare(pk_value) == 0;
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
    return ret;
}

bool SQLiteDBEngine::updateRows(const std::string& table,
                                const std::vector<std::string>& primaryKeyList,
                                std::vector<Row>& rowKeysValue)
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

bool SQLiteDBEngine::getFieldValueFromTuple(const std::pair<const std::__cxx11::string, TableField> &value,
                                            nlohmann::json& object)
{
    auto ret { true };
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
        std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
        ret = false;
    }

    return ret;
}

bool SQLiteDBEngine::getFieldValueFromTuple(const std::pair<const std::__cxx11::string, TableField> &value,
                                            std::string& resultValue,
                                            const bool quotationMarks)
{
    auto ret { true };
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
        ret = false;
    }
    return ret;
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

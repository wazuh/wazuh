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

#pragma once
#include "dbengine.h"
#include "sqlite_wrapper_factory.h"
#include "isqlite_wrapper.h"
#include <tuple>
#include <iostream>

constexpr auto kTempTableSubFix {"_TEMP"};

enum ColumnType {
  UNKNOWN_TYPE = 0,
  TEXT_TYPE,
  INTEGER_TYPE,
  BIGINT_TYPE,
  UNSIGNED_BIGINT_TYPE,
  DOUBLE_TYPE,
  BLOB_TYPE,
};

const std::map<ColumnType, std::string> kColumnTypeNames = {
    {UNKNOWN_TYPE, "UNKNOWN"},
    {TEXT_TYPE, "TEXT"},
    {INTEGER_TYPE, "INTEGER"},
    {BIGINT_TYPE, "BIGINT"},
    {UNSIGNED_BIGINT_TYPE, "UNSIGNED BIGINT"},
    {DOUBLE_TYPE, "DOUBLE"},
    {BLOB_TYPE, "BLOB"},
};

enum TableHeader {
  CID = 0,
  NAME,
  TYPE,
  PK
}; 
using ColumnData = 
    std::tuple<int32_t, std::string, ColumnType, bool>;

using TableColumns =
    std::vector<ColumnData>;

enum GenericTupleIndex {
  GEN_TYPE = 0,
  GEN_STRING,
  GEN_INTEGER,
  GEN_BIGINT,
  GEN_UNSIGNED_BIGINT,
  GEN_DOUBLE
}; 

using TableField = 
    std::tuple<int32_t, std::string, int32_t, int64_t, uint64_t, double_t>;

using Row = std::map<std::string, TableField>;


enum ResponseType {
  RT_JSON = 0,
  RT_CALLBACK
}; 

class SQLiteDBEngine : public DbSync::IDbEngine {
public:
  SQLiteDBEngine(std::shared_ptr<ISQLiteFactory> sqlite_factory,const std::string& path, const std::string& table_statement_creation);
  ~SQLiteDBEngine();
  
  virtual void execute(const std::string& query) override;
  virtual void select(const std::string& query, nlohmann::json& result) override;
  virtual void bulkInsert(const std::string& table, const nlohmann::json& data) override;
  virtual void refreshTableData(const nlohmann::json& data, const std::tuple<nlohmann::json&, void *> delta) override;

private:
  void initialize(const std::string& path, const std::string& table_statement_creation);
  bool cleanDB(const std::string& path);
  
  size_t loadTableData(const std::string& table);
  bool loadFieldData(const std::string& table);
  std::string buildInsertBulkDataSqlQuery(const std::string& table);
  std::string buildDeleteBulkDataSqlQuery(const std::string& table, const std::vector<std::string>& primary_key_list);
  ColumnType columnTypeName(const std::string& type);
  void bindJsonData(std::unique_ptr<SQLite::IStatement>const & stmt, const ColumnData& cd, const nlohmann::json::value_type& value_type);

  bool createCopyTempTable(const std::string& table);
  bool getTableCreateQuery(const std::string& table, std::string& result_query);
  bool getPrimaryKeysFromTable(const std::string& table, std::vector<std::string>& primary_key_list);

  bool removeNotExistsRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::tuple<nlohmann::json&, void *> delta);
  bool insertNewRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::tuple<nlohmann::json&, void *> delta);

  bool deleteRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::vector<Row>& rows_to_remove);
  int32_t getTableData(std::unique_ptr<SQLite::IStatement>const & stmt, const int32_t index, const ColumnType& type, const std::string& field_name, Row& row);
  int32_t bindFieldData(std::unique_ptr<SQLite::IStatement>const & stmt, const int32_t index, const TableField& field_data);

  std::string buildLeftOnlyQuery(const std::string& t1,const std::string& t2,const std::vector<std::string>& primary_key_list, const bool return_only_pk_fields = false);
  bool getLeftOnly(const std::string& t1,const std::string& t2, const std::vector<std::string>& primary_key_list, std::vector<Row>& return_rows);
  bool getPKListLeftOnly(const std::string& t1, const std::string& t2, const std::vector<std::string>& primary_key_list, std::vector<Row>& return_rows);
  void bulkInsert(const std::string& table, const std::vector<Row>& data);
  void deleteTempTable(const std::string& table);

  std::string buildModifiedRowsQuery(const std::string& t1,const std::string& t2, const std::vector<std::string>& primary_key_list);
  int changeModifiedRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::tuple<nlohmann::json&, void *> delta);
  std::string buildUpdateDataSqlQuery(const std::string& table, const std::vector<std::string>& primary_key_list, const Row& row, const std::pair<const std::__cxx11::string, TableField> &field);

  bool getRowsToModify(const std::string& table, const std::vector<std::string>& primary_key_list, std::vector<Row>& row_keys_value);
  bool updateRows(const std::string& table, const std::vector<std::string>& primary_key_list, std::vector<Row>& row_keys_value);

  bool getFieldValueFromTuple(const std::pair<const std::__cxx11::string, TableField> &value, std::string& result_value, const bool quotation_marks = false);
  bool getFieldValueFromTuple(const std::pair<const std::__cxx11::string, TableField> &value, nlohmann::json& object);

  SQLiteDBEngine(const SQLiteDBEngine&) = delete;
  SQLiteDBEngine& operator=(const SQLiteDBEngine&) = delete;

  std::unique_ptr<SQLite::IStatement>const& getStatement(const std::string& sql);

  std::map<std::string, TableColumns> m_table_fields;
  std::map<std::string, std::unique_ptr<SQLite::IStatement>> m_statements_cache;
  std::shared_ptr<ISQLiteFactory> m_sqlite_factory;
  std::shared_ptr<SQLite::IConnection> m_sqlite_connection;

};
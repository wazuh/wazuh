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

class SQLiteDBEngine : public DbEngine {
public:
  SQLiteDBEngine(std::shared_ptr<ISQLiteFactory> sqlite_factory,const std::string& path, const std::string& table_statement_creation);
  ~SQLiteDBEngine();
  
  virtual bool Execute(const std::string& query) override;
  virtual bool Select(const std::string& query, nlohmann::json& result) override;
  virtual bool BulkInsert(const std::string& table, const nlohmann::json& data) override; 
  virtual bool RefreshTablaData(const nlohmann::json& data, const std::tuple<nlohmann::json&, void *> delta) override;

private:
  void Initialize(const std::string& path, const std::string& table_statement_creation);
  bool CleanDB(const std::string& path);
  
  size_t LoadTableData(const std::string& table);
  bool LoadFieldData(const std::string& table);
  std::string BuildInsertBulkDataSqlQuery(const std::string& table);
  std::string BuildDeleteBulkDataSqlQuery(const std::string& table, const std::vector<std::string>& primary_key_list);
  ColumnType ColumnTypeName(const std::string& type);
  bool BindJsonData(std::unique_ptr<SQLite::IStatement>const & stmt, const ColumnData& cd, const nlohmann::json::value_type& value_type);

  bool CreateCopyTempTable(const std::string& table);
  bool GetTableCreateQuery(const std::string& table, std::string& result_query);
  bool GetPrimaryKeysFromTable(const std::string& table, std::vector<std::string>& primary_key_list);

  bool RemoveNotExistsRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::tuple<nlohmann::json&, void *> delta);
  bool InsertNewRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::tuple<nlohmann::json&, void *> delta);

  bool DeleteRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::vector<Row>& rows_to_remove); 
  int32_t GetTableData(std::unique_ptr<SQLite::IStatement>const & stmt, const int32_t index, const ColumnType& type, const std::string& field_name, Row& row);
  int32_t BindFieldData(std::unique_ptr<SQLite::IStatement>const & stmt, const int32_t index, const TableField& field_data);

  std::string BuildLeftOnlyQuery(const std::string& t1,const std::string& t2,const std::vector<std::string>& primary_key_list, const bool return_only_pk_fields = false);
  bool GetLeftOnly(const std::string& t1,const std::string& t2, const std::vector<std::string>& primary_key_list, std::vector<Row>& return_rows);
  bool GetPKListLeftOnly(const std::string& t1, const std::string& t2, const std::vector<std::string>& primary_key_list, std::vector<Row>& return_rows);
  bool BulkInsert(const std::string& table, const std::vector<Row>& data);
  void DeleteTempTable(const std::string& table);

  std::string BuildModifiedRowsQuery(const std::string& t1,const std::string& t2, const std::vector<std::string>& primary_key_list);
  int ChangeModifiedRows(const std::string& table, const std::vector<std::string>& primary_key_list, const std::tuple<nlohmann::json&, void *> delta);
  std::string BuildUpdateDataSqlQuery(const std::string& table, const std::vector<std::string>& primary_key_list, const Row& row, const std::pair<const std::__cxx11::string, TableField> &field);

  bool GetRowsToModify(const std::string& table, const std::vector<std::string>& primary_key_list, std::vector<Row>& row_keys_value);
  bool UpdateRows(const std::string& table, const std::vector<std::string>& primary_key_list, std::vector<Row>& row_keys_value);

  bool GetFieldValueFromTuple(const std::pair<const std::__cxx11::string, TableField> &value, std::string& result_value, const bool quotation_marks = false);
  bool GetFieldValueFromTuple(const std::pair<const std::__cxx11::string, TableField> &value, nlohmann::json& object);

  SQLiteDBEngine(const SQLiteDBEngine&) = delete;
  SQLiteDBEngine& operator=(const SQLiteDBEngine&) = delete;

  std::unique_ptr<SQLite::IStatement>const& GetStatement(const std::string& sql);

  std::map<std::string, TableColumns> m_table_fields;
  std::map<std::string, std::unique_ptr<SQLite::IStatement>> m_statements_cache;
  sqlite3* m_db;
  std::shared_ptr<ISQLiteFactory> m_sqlite_factory;
  std::shared_ptr<SQLite::IConnection> m_sqlite_connection;

};
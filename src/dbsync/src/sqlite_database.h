#pragma once
#include "database.h"
#include <sqlite3.h>
#include <tuple>
#include <iostream>


enum class ColumnOptions {
  /// Default/no options.
  DEFAULT = 0,

  /// Treat this column as a primary key.
  INDEX = 1,

  /// This column MUST be included in the query predicate.
  REQUIRED = 2,

  /*
   * @brief This column is used to generate additional information.
   *
   * If this column is included in the query predicate, the table will generate
   * additional information. Consider the browser_plugins or shell history
   * tables: by default they list the plugins or history relative to the user
   * running the query. However, if the calling query specifies a UID explicitly
   * in the predicate, the meaning of the table changes and results for that
   * user are returned instead.
   */
  ADDITIONAL = 4,

  /*
   * @brief This column can be used to optimize the query.
   *
   * If this column is included in the query predicate, the table will generate
   * optimized information. Consider the system_controls table, a default filter
   * without a query predicate lists all of the keys. When a specific domain is
   * included in the predicate then the table will only issue syscalls/lookups
   * for that domain, greatly optimizing the time and utilization.
   *
   * This optimization does not mean the column is an index.
   */
  OPTIMIZED = 8,

  /// This column should be hidden from '*'' selects.
  HIDDEN = 16,
};

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
using ColumnData = std::tuple<int32_t, std::string, ColumnType, bool>;
using TableColumns =
    std::vector<ColumnData>;

class SQLiteDB : public Database {
public:
  SQLiteDB(const std::string& path, const std::string& table_statement_creation);
  ~SQLiteDB();
  
  virtual bool Execute(const std::string& query) override;
  virtual bool Select(const std::string& query, std::vector<std::string>& result) override;
  virtual bool BulkInsert(const nlohmann::json& data) override;

private:
  bool Open(const std::string& path);
  bool Initialize(const std::string& path, const std::string& table_statement_creation);
  bool CleanOldDB(const std::string& path);
  
  size_t LoadTableData(const std::string& table);
  bool LoadFieldData(const std::string& table);
  std::string BuildInsertBulkDataSqlQuery(const std::string& table);
  ColumnType ColumnTypeName(const std::string& type);
  int32_t BindJsonData(sqlite3_stmt* stmt, const ColumnData& cd, const nlohmann::json::value_type& value_type);

  SQLiteDB(const SQLiteDB&) = delete;
  SQLiteDB& operator=(const SQLiteDB&) = delete;

  std::map<std::string, TableColumns> m_table_fields;
  sqlite3* m_db;

};
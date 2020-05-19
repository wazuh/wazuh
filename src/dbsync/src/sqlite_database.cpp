#include "sqlite_database.h"
#include <fstream>

bool SQLiteDB::Execute(
    const std::string& query) {

    return true;
}

bool SQLiteDB::Select(
    const std::string& query, 
    std::vector<std::string>& result) {

    return true;
}


SQLiteDB::SQLiteDB(
  const std::string& path, 
  const std::string& table_statement_creation) {

    if (!Initialize(path, table_statement_creation)) {
      throw std::runtime_error("Error during the SQLiteDB initialization.");
    }
}

SQLiteDB::~SQLiteDB() {
    if (m_db) {
      sqlite3_close_v2(m_db);
    }
}


bool SQLiteDB::Initialize(
  const std::string& path, 
  const std::string& table_statement_creation) {

  auto ret_val{ false };
  
  sqlite3_stmt *stmt;

  if (CleanOldDB(path)) {
    if (SQLITE_OK == sqlite3_open_v2(path.c_str(), &m_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
      const char* tail = nullptr;
      for (auto sql = table_statement_creation.c_str(); sql && *sql; sql = tail) {
        if (SQLITE_OK == sqlite3_prepare_v2(m_db, sql, -1, &stmt, &tail)) {
          if (SQLITE_DONE == sqlite3_step(stmt)) {
            ret_val = true;
          }
          else {
              std::cout << "Stepping statement: " << sqlite3_errmsg(m_db) << std::endl;
          } 
          sqlite3_finalize(stmt);
        } else {
          std::cout << "Preparing statement:: " << sqlite3_errmsg(m_db) << std::endl;
        }
      }
    } else {
      std::cout << "Couldn't create SQLite database: " << path << " - "<<sqlite3_errmsg(m_db) << std::endl;
    }

    if (!ret_val) {
      sqlite3_close_v2(m_db);
      m_db = nullptr;
    }
  }
  return ret_val;
}

bool SQLiteDB::CleanOldDB(const std::string& path) {
  auto ret_val { true };
  if (path.compare(":memory") != 0) {
    if (std::ifstream(path)){
      if (0 != std::remove(path.c_str())) {
        ret_val = false;
      }
    }
  }
  return ret_val;
}

bool SQLiteDB::BulkInsert(const nlohmann::json& data) {
    auto ret_val{ false };

    char* errorMessage;

    sqlite3_exec(m_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);

    const std::string table { data["table"].is_string() ? data["table"].get<std::string>() : "" };

    if (0 != LoadTableData(table)) {
      const auto sql { BuildInsertBulkDataSqlQuery(table) };

      if(!sql.empty()) {
        sqlite3_stmt* stmt{ nullptr };
        int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);

        if( rc == SQLITE_OK ) {
          for (const auto& json_value : data["data"]){
            for (const auto& value : m_table_fields[table]) {
              rc = BindJsonData(stmt, value, json_value);
            }

            int retVal = sqlite3_step(stmt);
            if (retVal != SQLITE_DONE)
            {
                printf("Commit Failed! %d\n", retVal);
            }

            sqlite3_reset(stmt);
          }

          ret_val = SQLITE_OK == sqlite3_exec(m_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);

          sqlite3_finalize(stmt);
        }else{
            fprintf(stderr, "SQL error: %s\n", errorMessage);
            sqlite3_free(errorMessage);
        }
      }
    }
    
    return ret_val;
}

size_t SQLiteDB::LoadTableData(const std::string& table) {
  size_t fields_quantity {0ull};
  if (0 == m_table_fields[table].size()) {
    if (LoadFieldData(table)) {
      fields_quantity = m_table_fields[table].size();
    }
  }

  return fields_quantity;    
}



std::string SQLiteDB::BuildInsertBulkDataSqlQuery(const std::string& table) {
    std::string sql = "INSERT INTO ";
    sql.append(table);
    sql.append(" VALUES (");

    if (0 != m_table_fields[table].size()) {
      for (size_t i = 0; i < m_table_fields[table].size();++i) {
        sql.append("?,");
      }
      sql = sql.substr(0, sql.size()-1);
      sql.append(");");
    } else {
      sql.clear();
    }
    return sql;
}

bool SQLiteDB::LoadFieldData(const std::string& table) {
  auto ret_val { false };
  sqlite3_stmt* stmt{ nullptr };
  const std::string q {"PRAGMA table_info("+table+");"}; 
  
  if (!table.empty()) {
    auto rc = sqlite3_prepare_v2(m_db,
                                  q.c_str(),
                                  -1,
                                  &stmt,
                                  nullptr);
    if (rc == SQLITE_OK) {
      while (SQLITE_ROW == sqlite3_step(stmt)) {
        m_table_fields[table].push_back(std::make_tuple(
            sqlite3_column_int(stmt, 0), 
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)), 
            ColumnTypeName(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2))), 
            1 == sqlite3_column_int(stmt, 5) ? true : false));
      }

      sqlite3_finalize(stmt);
      ret_val = true;
    } else {
      sqlite3_errmsg(m_db);
    }
  }
  return ret_val;
}


ColumnType SQLiteDB::ColumnTypeName(const std::string& type) {
  for (const auto& col : kColumnTypeNames) {
    if (col.second == type) {
      return col.first;
    }
  }
  return UNKNOWN_TYPE;
}

int32_t SQLiteDB::BindJsonData(sqlite3_stmt* stmt, const ColumnData& cd, const nlohmann::json::value_type& value_type){
  auto type = std::get<TableHeader::TYPE>(cd);
  auto cid = std::get<TableHeader::CID>(cd) + 1;
  auto name = std::get<TableHeader::NAME>(cd);

  int32_t rc = SQLITE_ERROR;
  
  if (ColumnType::BIGINT_TYPE == type) {
    int64_t value = value_type[name].is_number() ? value_type[name].get<int64_t>()  : 0;
    rc = sqlite3_bind_int(stmt,  
                            cid, 
                            value);
  } else if (ColumnType::UNSIGNED_BIGINT_TYPE == type) {
    uint64_t value = value_type[name].is_number_unsigned() ? value_type[name].get<uint64_t>()  : 0;
    rc = sqlite3_bind_int(stmt,  
                            cid, 
                            value);
  } else if (ColumnType::INTEGER_TYPE == type) {
    int32_t value = value_type[name].is_number() ? value_type[name].get<int32_t>()  : 0;
    rc = sqlite3_bind_int(stmt,  
                            cid, 
                            value);
  } else if (ColumnType::TEXT_TYPE == type) {
    std::string value = value_type[name].is_string() ? value_type[name].get<std::string>() : "";
    rc = sqlite3_bind_text(stmt,  
                            cid, 
                            value.c_str(), 
                            value.length(), 
                            SQLITE_TRANSIENT);
  } else if (ColumnType::DOUBLE_TYPE == type) {
    double value = value_type[name].is_number_float() ? value_type[name].get<double>() : .0f;
    rc = sqlite3_bind_double(stmt,  
                            cid, 
                            value);

  } else if (ColumnType::BLOB_TYPE == type) {
    std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
  }

  return rc;
}
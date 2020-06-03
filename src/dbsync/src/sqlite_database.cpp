#include "sqlite_database.h"
#include "string_helper.h"
#include <fstream>

bool SQLiteDB::Execute(
    const std::string& query) {

    return true;
}

bool SQLiteDB::Select(
    const std::string& query, 
    nlohmann::json& result) {

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

  if (CleanDB(path)) {
    if (SQLITE_OK == sqlite3_open_v2(path.c_str(), &m_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
      sqlite3_exec(m_db, "PRAGMA temp_store = memory;", 0,0, nullptr);
      sqlite3_exec(m_db, "PRAGMA synchronous = OFF", 0, 0, nullptr);

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

bool SQLiteDB::CleanDB(const std::string& path) {
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

bool SQLiteDB::BulkInsert(const std::string& table, const nlohmann::json& data) {
    auto ret_val{ false };

    char* errorMessage;

    sqlite3_exec(m_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);

    if (0 != LoadTableData(table)) {
      const auto sql { BuildInsertBulkDataSqlQuery(table) };

      if(!sql.empty()) {
        sqlite3_stmt* stmt{ nullptr };
        int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);

        if( rc == SQLITE_OK ) {
          for (const auto& json_value : data){
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
  } else {
    fields_quantity = m_table_fields[table].size();
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
  const auto type = std::get<TableHeader::TYPE>(cd);
  const auto cid = std::get<TableHeader::CID>(cd) + 1;
  const auto name = std::get<TableHeader::NAME>(cd);

  int32_t rc = SQLITE_ERROR;
  
  if (ColumnType::BIGINT_TYPE == type) {
    int64_t value = value_type[name].is_number() ? value_type[name].get<int64_t>() : 0;
    rc = sqlite3_bind_int(stmt,  
                            cid, 
                            value);
  } else if (ColumnType::UNSIGNED_BIGINT_TYPE == type) {
    uint64_t value = value_type[name].is_number_unsigned() ? value_type[name].get<uint64_t>() : 0;
    rc = sqlite3_bind_int(stmt,  
                            cid, 
                            value);
  } else if (ColumnType::INTEGER_TYPE == type) {
    int32_t value = value_type[name].is_number() ? value_type[name].get<int32_t>() : 0;
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

bool SQLiteDB::RefreshTablaData(const nlohmann::json& data, nlohmann::json& delta) {
  auto ret_val {false};
  const std::string table { data["table"].is_string() ? data["table"].get<std::string>() : "" };
  if (CreateCopyTempTable(table)) {
    if (BulkInsert(table + kTempTableSubFix, data["data"])) {
      std::vector<std::string> primary_key_list;
      if (GetPrimaryKeysFromTable(table, primary_key_list)) {
        if (!RemoveNotExistsRows(table, primary_key_list, delta)) {
          std::cout << "Error during the delete rows update "<< __LINE__ << " - " << __FILE__ << std::endl;
        }
        if (!ChangeModifiedRows(table, primary_key_list, delta)) {
          std::cout << "Error during the change of modified rows" << __LINE__ << " - " << __FILE__ << std::endl;
        }
        if (!InsertNewRows(table, primary_key_list, delta)) {
          std::cout << "Error during the insert rows update "<< __LINE__ << " - " << __FILE__ << std::endl;
        }
        
      }
      ret_val = true;
    }
    DeleteTempTable(table);
  }
  return ret_val;
}

bool SQLiteDB::CreateCopyTempTable(const std::string& table) {
  auto ret_val { false };
  sqlite3_stmt* stmt{ nullptr };
  std::string result_query;
  if (GetTableCreateQuery(table, result_query)) {
    if(StringHelper::replace_string(result_query, "CREATE TABLE " + table, "CREATE TEMP TABLE "+table+"_TEMP")) {
      if (SQLITE_OK == sqlite3_prepare_v2(m_db, result_query.c_str(), -1, &stmt, nullptr)) {
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
  }
  return ret_val;
}

int SQLiteDB::DeleteTempTable(const std::string& table) { 
  
  char* errorMessage { nullptr };
  const std::string query { "DROP TABLE " + table + kTempTableSubFix + ";" };
  auto ret_val { sqlite3_exec(m_db, query.c_str(), NULL, NULL, &errorMessage) };
  if(SQLITE_OK != ret_val) {
      fprintf(stderr, "SQL error: %s\n", errorMessage);
      sqlite3_free(errorMessage);
  }
  return ret_val;
}

bool SQLiteDB::GetTableCreateQuery(const std::string& table, std::string& result_query)
{
  auto ret_val { false };
  sqlite3_stmt* stmt{ nullptr };
  const std::string q {"select sql from sqlite_master where type='table' AND name=?;"}; 

  if (!table.empty()) {
    auto rc = sqlite3_prepare_v2(m_db,
                                  q.c_str(),
                                  -1,
                                  &stmt,
                                  nullptr);
    if (rc == SQLITE_OK) {
      rc = sqlite3_bind_text(stmt,  
                            1, 
                            table.c_str(), 
                            table.length(), 
                            SQLITE_TRANSIENT);
      if (rc == SQLITE_OK) {
       if (SQLITE_ROW == sqlite3_step(stmt)) {
          result_query.append(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
          result_query.append(";");
          ret_val = true;
        }
      }
      sqlite3_finalize(stmt);
    } else {
      sqlite3_errmsg(m_db);
    }
  }
  return ret_val;
}

bool SQLiteDB::RemoveNotExistsRows(const std::string& table, const std::vector<std::string>& primary_key_list, nlohmann::json& delta) {
  auto ret_val {true  };
  std::vector<Row> row_keys_value;
  if (GetPKListLeftOnly(table, table+kTempTableSubFix, primary_key_list, row_keys_value)) {
    if (DeleteRows(table, primary_key_list, row_keys_value)) {
      for (const auto& row : row_keys_value){
        nlohmann::json object;
        for (const auto& value : row) {
          const auto row_type { std::get<GenericTupleIndex::GEN_TYPE>(value.second) };
          if (ColumnType::BIGINT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::BIGINT_TYPE>(value.second);
          } else if (ColumnType::UNSIGNED_BIGINT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::UNSIGNED_BIGINT_TYPE>(value.second);
          } else if (ColumnType::INTEGER_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::INTEGER_TYPE>(value.second);
          } else if (ColumnType::TEXT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::TEXT_TYPE>(value.second);
          } else if (ColumnType::DOUBLE_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::DOUBLE_TYPE>(value.second);
          } else if (ColumnType::BLOB_TYPE == row_type) {
            std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
          }
        }
        delta["deleted"].push_back(std::move(object));
      }
    } else {
      ret_val = false;
    }
  }
  return ret_val;
}

bool SQLiteDB::GetPrimaryKeysFromTable(const std::string& table, std::vector<std::string>& primary_key_list) {
    
    for(const auto& value : m_table_fields[table]) {
      if (std::get<TableHeader::PK>(value) == true) {
        primary_key_list.push_back(std::get<TableHeader::NAME>(value));
      }
    }
    return m_table_fields.find(table) != m_table_fields.end();
}

int32_t SQLiteDB::GetTableData(sqlite3_stmt* stmt, const int32_t index, const ColumnType& type, const std::string& field_name, Row& row) {
 
  int32_t rc { SQLITE_OK };
 
  if (ColumnType::BIGINT_TYPE == type) {
    row[field_name] = std::make_tuple(type,std::string(),0,sqlite3_column_int64(stmt, index),0,0);
  } else if (ColumnType::UNSIGNED_BIGINT_TYPE == type) {
    row[field_name] = std::make_tuple(type,std::string(),0,0,sqlite3_column_int64(stmt, index),0);                        
  } else if (ColumnType::INTEGER_TYPE == type) {
    row[field_name] = std::make_tuple(type,std::string(),sqlite3_column_int(stmt, index),0,0,0); 
  } else if (ColumnType::TEXT_TYPE == type) {
    row[field_name] = std::make_tuple(type,reinterpret_cast<const char *>(sqlite3_column_text(stmt, index)),0,0,0,0); 
  } else if (ColumnType::DOUBLE_TYPE == type) {
    row[field_name] = std::make_tuple(type,std::string(),0,0,0,sqlite3_column_double(stmt, index)); 
  } else if (ColumnType::BLOB_TYPE == type) {
    std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
  } else {
    rc = SQLITE_ERROR;
  }

  return rc;
}

bool SQLiteDB::GetLeftOnly(
  const std::string& t1, 
  const std::string& t2, 
  const std::vector<std::string>& primary_key_list, 
  std::vector<Row>& return_rows) {

  sqlite3_stmt* stmt{ nullptr };
  auto ret_val { false };
  
  const std::string query { BuildLeftOnlyQuery(t1, t2, primary_key_list) };

  if (!t1.empty() && !query.empty()) {
    auto rc = sqlite3_prepare_v2(m_db,
                                  query.c_str(),
                                  -1,
                                  &stmt,
                                  nullptr);
    if (rc == SQLITE_OK) {
      const auto table_fields { m_table_fields[t1] };
      while (SQLITE_ROW == sqlite3_step(stmt)) {
        Row register_fields;
        for(const auto& field : table_fields) {
          GetTableData(
            stmt, 
            std::get<TableHeader::CID>(field), 
            std::get<TableHeader::TYPE>(field),
            std::get<TableHeader::NAME>(field), 
            register_fields);
        }
        return_rows.push_back(std::move(register_fields));
      }

      sqlite3_finalize(stmt);
      ret_val = true;
    } else {
      sqlite3_errmsg(m_db);
    }
  } 

  return ret_val;
}

bool SQLiteDB::GetPKListLeftOnly(
  const std::string& t1, 
  const std::string& t2, 
  const std::vector<std::string>& primary_key_list, 
  std::vector<Row>& return_rows) {

  sqlite3_stmt* stmt{ nullptr };
  auto ret_val { false };
  
  const std::string query { BuildLeftOnlyQuery(t1, t2, primary_key_list, true) };

  if (!t1.empty() && !query.empty()) {
    auto rc = sqlite3_prepare_v2(m_db,
                                  query.c_str(),
                                  -1,
                                  &stmt,
                                  nullptr);
    if (rc == SQLITE_OK) {
      const auto table_fields { m_table_fields[t1] };
      while (SQLITE_ROW == sqlite3_step(stmt)) {
        Row register_fields;
        for(const auto& value_pk : primary_key_list) {
          auto index { 0ull };
          const auto& it = std::find_if(
            table_fields.begin(), 
            table_fields.end(), 
            [&value_pk](const ColumnData& column_data) {
              return std::get<TableHeader::NAME>(column_data) == value_pk;
          });

          if (table_fields.end() != it) { 
            GetTableData(
            stmt, 
            index, 
            std::get<TableHeader::TYPE>(*it),
            std::get<TableHeader::NAME>(*it), 
            register_fields);
          }
          ++index;
        }
        return_rows.push_back(std::move(register_fields));
      }

      sqlite3_finalize(stmt);
      ret_val = true;
    } else {
      sqlite3_errmsg(m_db);
    }
  } 

  return ret_val;
}

std::string SQLiteDB::BuildDeleteBulkDataSqlQuery(const std::string& table, const std::vector<std::string>& primary_key_list) {
    std::string sql = "DELETE FROM ";
    sql.append(table);
    sql.append(" WHERE ");

    if (0 != primary_key_list.size()) {
      for (const auto& value : primary_key_list) {
        sql.append(value);
        sql.append("=? AND ");
      }
      sql = sql.substr(0, sql.size()-5);
      sql.append(";");
    } else {
      sql.clear();
    }
    return sql;
}

bool SQLiteDB::DeleteRows(
  const std::string& table, 
  const std::vector<std::string>& primary_key_list,
  const std::vector<Row>& rows_to_remove) {

  auto ret_val { false };
  char* errorMessage;

  sqlite3_exec(m_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);

  const auto sql { BuildDeleteBulkDataSqlQuery(table, primary_key_list) };

  if(!sql.empty()) {
    sqlite3_stmt* stmt{ nullptr };
    auto rc { sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) };

    if( rc == SQLITE_OK ) {
      for (const auto& row : rows_to_remove){
        auto index {1l};
        for (const auto& value : primary_key_list) {
          rc = BindFieldData(stmt, index, row.at(value) );
          ++index;
        }

        if (SQLITE_DONE != sqlite3_step(stmt)) {
          std::cout << "Commit Error" << std::endl;
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
  
  return ret_val;
}


int32_t SQLiteDB::BindFieldData(sqlite3_stmt* stmt, const int32_t index, const TableField& field_data){

  int32_t rc = SQLITE_ERROR;

  const auto type = std::get<GenericTupleIndex::GEN_TYPE>(field_data);
  
  if (ColumnType::BIGINT_TYPE == type) {
    const auto value { std::get<GenericTupleIndex::GEN_BIGINT>(field_data) };
    rc = sqlite3_bind_int(stmt,  
                            index, 
                            value);
  } else if (ColumnType::UNSIGNED_BIGINT_TYPE == type) {
    const auto value { std::get<GenericTupleIndex::GEN_UNSIGNED_BIGINT>(field_data) };
    rc = sqlite3_bind_int(stmt,  
                            index, 
                            value);
  } else if (ColumnType::INTEGER_TYPE == type) {
    const auto value { std::get<GenericTupleIndex::GEN_INTEGER>(field_data) };
    rc = sqlite3_bind_int(stmt,  
                            index, 
                            value);
  } else if (ColumnType::TEXT_TYPE == type) {
    const auto value { std::get<GenericTupleIndex::GEN_STRING>(field_data) };
    rc = sqlite3_bind_text(stmt,  
                            index, 
                            value.c_str(), 
                            value.length(), 
                            SQLITE_TRANSIENT);
  } else if (ColumnType::DOUBLE_TYPE == type) {
    const auto value { std::get<GenericTupleIndex::GEN_DOUBLE>(field_data) };
    rc = sqlite3_bind_double(stmt,  
                            index, 
                            value);

  } else if (ColumnType::BLOB_TYPE == type) {
    std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
  }

  return rc;
}


std::string SQLiteDB::BuildLeftOnlyQuery(
  const std::string& t1,
  const std::string& t2,
  const std::vector<std::string>& primary_key_list,
  const bool return_only_pk_fields) {

  std::string return_fields_list;
  std::string on_match_list;
  std::string null_filter_list;
  
  for (const auto& value : primary_key_list) {
    if (return_only_pk_fields)
      return_fields_list.append("t1."+value+",");
    on_match_list.append("t1." + value + "= t2." + value + " AND ");
    null_filter_list.append("t2."+value+ " IS NULL AND ");
  }

  if (return_only_pk_fields)
    return_fields_list = return_fields_list.substr(0, return_fields_list.size()-1);
  else
    return_fields_list.append("*");
  on_match_list = on_match_list.substr(0, on_match_list.size()-5);
  null_filter_list = null_filter_list.substr(0, null_filter_list.size()-5);


  return std::string("SELECT "+return_fields_list+" FROM "+t1+" t1 LEFT JOIN "+t2+" t2 ON "+on_match_list+" WHERE "+null_filter_list+";");
} 


bool SQLiteDB::InsertNewRows(const std::string& table, const std::vector<std::string>& primary_key_list, nlohmann::json& delta) {
  auto ret_val { true };
  std::vector<Row> row_values;
  if (GetLeftOnly(table+kTempTableSubFix, table, primary_key_list, row_values)) {
     if (BulkInsert(table, row_values)) {
       for (const auto& row : row_values){
        nlohmann::json object;
        for (const auto& value : row) {
          const auto row_type { std::get<GenericTupleIndex::GEN_TYPE>(value.second) };
          if (ColumnType::BIGINT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::BIGINT_TYPE>(value.second);
          } else if (ColumnType::UNSIGNED_BIGINT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::UNSIGNED_BIGINT_TYPE>(value.second);
          } else if (ColumnType::INTEGER_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::INTEGER_TYPE>(value.second);
          } else if (ColumnType::TEXT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::TEXT_TYPE>(value.second);
          } else if (ColumnType::DOUBLE_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::DOUBLE_TYPE>(value.second);
          } else if (ColumnType::BLOB_TYPE == row_type) {
            std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
          }
        }
        delta["inserted"].push_back(std::move(object));
      }
    } 
    else {
      ret_val = false;
    }
  }
  return ret_val;
}

bool SQLiteDB::BulkInsert(const std::string& table, const std::vector<Row>& data) {
    auto ret_val{ false };

    char* errorMessage;

    sqlite3_exec(m_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);

    const auto sql { BuildInsertBulkDataSqlQuery(table) };

    if(!sql.empty()) {
      sqlite3_stmt* stmt{ nullptr };
      auto rc { sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) };

      if( rc == SQLITE_OK ) {
        for (const auto& row : data){
          for (const auto& value : m_table_fields[table]) {
            auto it { row.find(std::get<TableHeader::NAME>(value))};
            if (row.end() != it){
              rc = BindFieldData(stmt, std::get<TableHeader::CID>(value) + 1, (*it).second );
            }
          }

          if (SQLITE_DONE != sqlite3_step(stmt)) {
            std::cout << "Commit Error" << std::endl;
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
    
    return ret_val;
}

int SQLiteDB::ChangeModifiedRows(const std::string& table, const std::vector<std::string>& primary_key_list, nlohmann::json& delta) {
  auto ret_val {true  };
  std::vector<Row> row_keys_value;
  if (GetModifiedTableRows(table, table+kTempTableSubFix, primary_key_list, row_keys_value)) {
    if (PreparedTransactionExecute( 
      BuildUpdateDataSqlQuery(table, primary_key_list), 
      [&](sqlite3_stmt* stmt){
        auto rc { SQLITE_DONE };
        for (const auto& rows : row_keys_value) {
          for (const auto& field : rows) {

            if (0 != field.first.substr(0,3).compare("PK_"))
            {
              auto index_pk { 2l };
  
              for (const auto& pk : primary_key_list) {
                BindFieldData(stmt, index_pk, rows.at("PK_"+pk));
                ++index_pk;
              }

              BindFieldData(stmt, 1, field.second);

              if (rc = sqlite3_step(stmt), SQLITE_DONE != rc) {
                std::cout << "Commit Error" << std::endl;
                sqlite3_reset(stmt);
                break;
              }
              sqlite3_reset(stmt);
            }
            
          }
        }
        return rc;
      })) {

      for (const auto& row : row_keys_value){
        nlohmann::json object;
        for (const auto& value : row) {
          const auto row_type { std::get<GenericTupleIndex::GEN_TYPE>(value.second) };
          if (ColumnType::BIGINT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::BIGINT_TYPE>(value.second);
          } else if (ColumnType::UNSIGNED_BIGINT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::UNSIGNED_BIGINT_TYPE>(value.second);
          } else if (ColumnType::INTEGER_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::INTEGER_TYPE>(value.second);
          } else if (ColumnType::TEXT_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::TEXT_TYPE>(value.second);
          } else if (ColumnType::DOUBLE_TYPE == row_type) {
            object[value.first] = std::get<ColumnType::DOUBLE_TYPE>(value.second);
          } else if (ColumnType::BLOB_TYPE == row_type) {
            std::cout << "not implemented "<< __LINE__ << " - " << __FILE__ << std::endl;
          }
        }
        delta["modified"].push_back(std::move(object));
      }
    } else {
      ret_val = false;
    }
  }
  return ret_val;
}

std::string SQLiteDB::BuildUpdateDataSqlQuery(const std::string& table, const std::vector<std::string>& primary_key_list) {
    std::string sql = "UPDATE ";
    sql.append(table);
    sql.append(" SET cmdline =?");
    sql.append(" WHERE ");

    if (0 != primary_key_list.size()) {
      for (const auto& value : primary_key_list) {
        sql.append(value);
        sql.append("=? AND ");
      }
      sql = sql.substr(0, sql.size()-5);
      sql.append(";");
    } else {
      sql.clear();
    }
    return sql;
}

int SQLiteDB::GetModifiedTableRows(
  const std::string& t1, 
  const std::string& t2, 
  const std::vector<std::string>& primary_key_list, 
  std::vector<Row>& return_rows) {

  sqlite3_stmt* stmt{ nullptr };
  auto ret_val { false };
  
  const std::string query { BuildModifiedRowsQuery(t1, t2, primary_key_list) };

  if (!t1.empty() && !query.empty()) {
    auto rc = sqlite3_prepare_v2(m_db,
                                  query.c_str(),
                                  -1,
                                  &stmt,
                                  nullptr);
    if (rc == SQLITE_OK) {
      while (SQLITE_ROW == sqlite3_step(stmt)) {
        const auto table_fields { m_table_fields[t1] };
        Row register_fields;
        int32_t index {0l};
        for(const auto& pk_value : primary_key_list) {
          const auto it = std::find_if(table_fields.begin(), table_fields.end(), [&pk_value] (const ColumnData& cd) {
            return std::get<TableHeader::NAME>(cd).compare(pk_value) == 0;
          });
          if (table_fields.end() != it) {
            GetTableData(
                        stmt, 
                        index, 
                        std::get<TableHeader::TYPE>(*it),
                        "PK_" + std::get<TableHeader::NAME>(*it), 
                        register_fields);
          }
          
          ++index;
        }
        for(const auto& field : table_fields) {
          if (register_fields.end() == register_fields.find(std::get<TableHeader::NAME>(field))){
            if (SQLITE_NULL != sqlite3_column_type(stmt, index)) {
              GetTableData(stmt, index, std::get<TableHeader::TYPE>(field), std::get<TableHeader::NAME>(field), register_fields);
            }
          }
          
          ++index;
        }
        return_rows.push_back(std::move(register_fields));
      }

      sqlite3_finalize(stmt);
      ret_val = true;
    } else {
      sqlite3_errmsg(m_db);
    }
  } 

  return ret_val;
}

std::string SQLiteDB::BuildModifiedRowsQuery(
  const std::string& t1,
  const std::string& t2,
  const std::vector<std::string>& primary_key_list) {

  std::string return_fields_list;
  std::string on_match_list;
  std::string null_filter_list;
  
  for (const auto& value : primary_key_list) {
    return_fields_list.append("t1."+value+",");
    on_match_list.append("t1." + value + "=t2." + value + " AND ");
  }

  for (const auto& value : m_table_fields[t1]) {
    const auto field_name {std::get<TableHeader::NAME>(value)};
    return_fields_list.append("CASE WHEN t1.");
    return_fields_list.append(field_name);
    return_fields_list.append("<>t2.");
    return_fields_list.append(field_name);
    return_fields_list.append(" THEN t1.");
    return_fields_list.append(field_name);
    return_fields_list.append(" ELSE NULL END AS DIF_");
    return_fields_list.append(field_name);
    return_fields_list.append(",");
  }

  return_fields_list = return_fields_list.substr(0, return_fields_list.size()-1);
  on_match_list = on_match_list.substr(0, on_match_list.size()-5);
  std::string ret_val {"SELECT "};
  ret_val.append(return_fields_list);
  ret_val.append(" FROM (select *,'");
  ret_val.append(t1);
  ret_val.append("' as val from ");
  ret_val.append(t1);
  ret_val.append(" UNION ALL select *,'");
  ret_val.append(t2);
  ret_val.append("' as val from ");
  ret_val.append(t2);
  ret_val.append(") t1 INNER JOIN ");
  ret_val.append(t1);
  ret_val.append(" t2 ON ");
  ret_val.append(on_match_list);
  ret_val.append(" WHERE t1.val = '");
  ret_val.append(t2);
  ret_val.append("';");
  
  return ret_val;
} 


bool SQLiteDB::PreparedTransactionExecute(
  const std::string& sql, 
  const std::function<int32_t(sqlite3_stmt*)>& bind_f) {

    auto ret_val{ false };
    char* errorMessage;

    if(!sql.empty()) {
      sqlite3_exec(m_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);

      sqlite3_stmt* stmt{ nullptr };
      auto rc { sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) };

      if( rc == SQLITE_OK ) {
        rc = bind_f(stmt);
        
        sqlite3_finalize(stmt);
        ret_val = SQLITE_OK == sqlite3_exec(m_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);
        
      }else{
          fprintf(stderr, "SQL error: %s\n", errorMessage);
          sqlite3_free(errorMessage);
      }
    }
    
    return ret_val;
}

bool SQLiteDB::TransactionExecute(
  const std::function<int32_t()>& bind_f) {

  auto ret_val{ false };
  char* errorMessage;

  sqlite3_exec(m_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);
  bind_f();
  ret_val = SQLITE_OK == sqlite3_exec(m_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);
    
  if (SQLITE_OK != ret_val){
      fprintf(stderr, "SQL error: %s\n", errorMessage);
      sqlite3_free(errorMessage);
  }
    
  return ret_val;
}
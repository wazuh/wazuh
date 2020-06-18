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

#include "sqlite_wrapper.h"
#include <iostream>
#include <chrono>

constexpr auto kDefaultPath {"temp.db"};

using namespace SQLite;

Connection::Connection(const std::string& path) : m_db_instance(nullptr) {
   if (SQLITE_OK != sqlite3_open_v2(path.c_str(), &m_db_instance, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
      throw SQLite::exception(600, "Unspecified type during initialization of SQLite.");
   }
}

Connection::~Connection() {
  Close();
}

bool Connection::Close() {
  auto ret_val { false };
  
  if (nullptr != m_db_instance) {
    ret_val = SQLITE_OK == sqlite3_close_v2(m_db_instance);
    m_db_instance = nullptr;
  }

  return ret_val;
}
sqlite3* Connection::GetDBInstance() {
  return m_db_instance;
}

Connection::Connection() : Connection(kDefaultPath){
}

bool Connection::Execute(const std::string& query) {
  auto ret_val{ false };
  if (nullptr != m_db_instance) {
    ret_val = SQLITE_OK == sqlite3_exec(m_db_instance, query.c_str(), 0,0, nullptr);
  }
  return ret_val;
}

Transaction::~Transaction() {
  if (!m_rollbacked && !m_commited) {
    m_connection->Execute("ROLLBACK TRANSACTION");
  }
}

Transaction::Transaction(std::shared_ptr<IConnection>& connection) : m_connection(connection){
  m_started = false;
  m_commited = false;
  m_rollbacked = false;

  if (m_connection->Execute("BEGIN TRANSACTION")) {
    m_started = true;
  }
}
    
bool Transaction::Commit() {
  if (m_started && 
  !m_rollbacked && 
  !m_commited) 
  {
    if (m_connection->Execute("COMMIT TRANSACTION")) {
      m_commited = true;
    }
  }
  return m_commited;
}

bool Transaction::Rollback() {
  if (m_started && 
  !m_rollbacked && 
  !m_commited) 
  {
    m_connection->Execute("ROLLBACK TRANSACTION");
    m_rollbacked = true;
  }
  return m_rollbacked;
}


Statement::Statement(std::shared_ptr<IConnection>& connection, const std::string& query) : m_connection(connection){
  if(SQLITE_OK != sqlite3_prepare_v2(connection->GetDBInstance(), query.c_str(), -1, &m_stmt, nullptr)) {
    throw SQLite::exception(601, "cannot instance SQLite stmt.");
  }
}

Statement::~Statement() { 
  sqlite3_finalize(m_stmt);
}

int32_t Statement::Step() {
  const auto ret_val { sqlite3_step(m_stmt) };
  if (SQLITE_ROW != ret_val && SQLITE_DONE != ret_val) {
    throw SQLite::exception(602, sqlite3_errmsg(m_connection->GetDBInstance()));
  }
  return ret_val;
}
bool Statement::Reset()  {
  return SQLITE_OK == sqlite3_reset(m_stmt);
}
bool Statement::Bind(const int32_t index, const int32_t value)  {
  return SQLITE_OK == sqlite3_bind_int(m_stmt, index, value);
}
bool Statement::Bind(const int32_t index, const uint64_t value)  {
  return SQLITE_OK == sqlite3_bind_int64(m_stmt, index, value);
}
bool Statement::Bind(const int32_t index, const int64_t value)  {
  return SQLITE_OK == sqlite3_bind_int64(m_stmt, index, value);
}
bool Statement::Bind(const int32_t index, const std::string value)  {
  return SQLITE_OK == sqlite3_bind_text(m_stmt,
                            index, 
                            value.c_str(), 
                            value.length(), 
                            SQLITE_TRANSIENT);
}
bool Statement::Bind(const int32_t index, const double value)  {
  return SQLITE_OK == sqlite3_bind_double(m_stmt, index, value);
}

std::unique_ptr<IColumn> Statement::GetColumn(const int32_t index)  {
  return std::make_unique<SQLite::Column>(m_stmt, index);
}

Column::Column(sqlite3_stmt* stmt, const int32_t index) : m_stmt(stmt), m_index(index){
}

bool Column::IsNullValue(){
  return SQLITE_NULL == sqlite3_column_type(m_stmt, m_index);
}
int32_t Column::Int(){;
  return sqlite3_column_int(m_stmt, m_index);
}
uint64_t Column::UInt64(){
  return sqlite3_column_int64(m_stmt, m_index); 
}
int64_t Column::Int64(){
  return sqlite3_column_int64(m_stmt, m_index);  
}
double Column::Double(){
  return sqlite3_column_double(m_stmt, m_index);
}
std::string Column::String(){
  return reinterpret_cast<const char *>(sqlite3_column_text(m_stmt, m_index));
}

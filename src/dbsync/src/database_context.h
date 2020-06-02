#pragma once
#include <memory>
#include <atomic>
#include "database.h"
#include "typedef.h"

static std::atomic_ullong g_handler = { 0ull };

class DatabaseContext {
public:
  DatabaseContext(
    std::unique_ptr<Database>& database, 
    const HostType host_type, 
    const DatabaseType db_type) : 
    m_database(std::move(database)),
    m_host_type(host_type),
    m_db_type(db_type),
    m_handler(++g_handler) {}

  const std::unique_ptr<Database>& GetDatabase() { return m_database; }
  const HostType& GetHostType() { return m_host_type; }
  const DatabaseType& GetDatabaseType() { return m_db_type; }
  const uint64_t& GetHandler() { return m_handler; }
private:
  std::unique_ptr<Database> m_database;
  HostType m_host_type;
  DatabaseType m_db_type;
  uint64_t m_handler;
};
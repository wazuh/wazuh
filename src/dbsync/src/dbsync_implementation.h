#pragma once
#include <vector>
#include <memory>
#include <mutex>

#include "database_factory.h"
#include "database_context.h"
#include "typedef.h"
#include "json.hpp"

class DBSyncImplementation {
public:
  static DBSyncImplementation& getInstance() {
    static DBSyncImplementation instance;
    return instance;
  }
  bool InsertBulkData(uint64_t handle, const char* json_raw);
  uint64_t Initialize(const HostType host_type, const DatabaseType db_type, const std::string& path, const std::string& sql_statement);
  bool Release();
private:
  std::vector<std::unique_ptr<DatabaseContext>>::iterator GetDatabaseContext(const uint64_t handler);

  DBSyncImplementation() = default;
  ~DBSyncImplementation() = default;
  DBSyncImplementation(const DBSyncImplementation&) = delete;
  DBSyncImplementation& operator=(const DBSyncImplementation&) = delete;

  std::vector<std::unique_ptr<DatabaseContext>> m_dbsync_list;
  std::mutex m_mutex;
};
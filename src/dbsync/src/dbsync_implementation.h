#pragma once
#include <vector>
#include <memory>
#include <mutex>

#include "dbengine_factory.h"
#include "dbengine_context.h"
#include "typedef.h"
#include "json.hpp"

class DBSyncImplementation {
public:
  static DBSyncImplementation& getInstance() {
    static DBSyncImplementation instance;
    return instance;
  }
  bool InsertBulkData(const uint64_t handle, const char* json_raw);
  bool UpdateSnapshotData(const uint64_t handle, const char* json_snapshot, std::string& result);
  bool UpdateSnapshotData(const uint64_t handle, const char* json_snapshot, void* callback);
  uint64_t Initialize(const HostType host_type, const DbEngineType db_type, const std::string& path, const std::string& sql_statement);
  bool Release();
private:
  std::vector<std::unique_ptr<DbEngineContext>>::iterator GetDbEngineContext(const uint64_t handler);

  DBSyncImplementation() = default;
  ~DBSyncImplementation() = default;
  DBSyncImplementation(const DBSyncImplementation&) = delete;
  DBSyncImplementation& operator=(const DBSyncImplementation&) = delete;

  std::vector<std::unique_ptr<DbEngineContext>> m_dbsync_list;
  std::mutex m_mutex;
};
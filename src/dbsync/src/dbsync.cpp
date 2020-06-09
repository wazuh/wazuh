#include "dbsync.h"
#include "dbsync_implementation.h"
#ifdef __cplusplus
extern "C" {
#endif

unsigned long long initialize(
    const HostType host_type, 
    const DbEngineType db_type,
    const char* path, 
    const char* sql_statement) {

  auto ret_val{ 0ull };

  if (nullptr == path ||
    nullptr == sql_statement) {
    std::cout << "Cannot initialize DBSyncImplementation" << std::endl;
  } else {
      ret_val = DBSyncImplementation::getInstance().Initialize(host_type, db_type, path, sql_statement);
  }
  return ret_val;
}

int insert_data(
  const unsigned long long handle,
  const cJSON* json_raw) {
  auto ret_val { 1l };
  if (nullptr != json_raw) {
    ret_val = DBSyncImplementation::getInstance().InsertBulkData(handle, cJSON_Print(json_raw));
  }
  return ret_val;
}

int update_with_snapshot(
    const unsigned long long handle,
    const cJSON* json_snapshot,
    cJSON** json_return_modifications)
{
  auto ret_val { false };
  if (nullptr != json_snapshot) {
    std::string result;
    ret_val = DBSyncImplementation::getInstance().UpdateSnapshotData(handle, cJSON_Print(json_snapshot), result);
    *json_return_modifications = cJSON_Parse(result.c_str());
  }
  return ret_val;
}

int update_with_snapshot_cb(
    const unsigned long long handle,
    const cJSON* json_snapshot,
    void* callback)
{
  auto ret_val { 0l };
  if (nullptr != json_snapshot) {
    ret_val = DBSyncImplementation::getInstance().UpdateSnapshotData(handle, cJSON_Print(json_snapshot), callback);
  }
  return ret_val;
}

void teardown(void) {
  if(!DBSyncImplementation::getInstance().Release()) {
    std::cout << "Error when release DBSyncImplementation" << std::endl;
  }
}

#ifdef __cplusplus
}
#endif
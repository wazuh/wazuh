#include "dbsync.h"
#include "dbsync_implementation.h"
#ifdef __cplusplus
extern "C" {
#endif

unsigned long long initialize(
    const HostType host_type, 
    const DatabaseType db_type,
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

bool insert_bulk(
  const unsigned long long handle,
  const char* json_raw) {
  auto ret_val { false };
  if (nullptr != json_raw) {
    ret_val = DBSyncImplementation::getInstance().InsertBulkData(handle, json_raw);
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
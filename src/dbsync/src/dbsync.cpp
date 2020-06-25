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

#include "dbsync.h"
#include "dbsync_implementation.h"
#ifdef __cplusplus
extern "C" {
#endif

struct CJsonDeleter
{
  void operator()(char* json)
  {
    cJSON_free(json);
  }
};

DBSYNC_HANDLE dbsync_initialize(
    const HostType host_type, 
    const DbEngineType db_type,
    const char* path, 
    const char* sql_statement) {

  DBSYNC_HANDLE ret_val{ nullptr };

  if (nullptr == path ||
    nullptr == sql_statement) {
    std::cout << "Cannot initialize DBSyncImplementation" << std::endl;
  } else {
      ret_val = DBSyncImplementation::getInstance().initialize(host_type, db_type, path, sql_statement);
  }
  return ret_val;
}

int dbsync_insert_data(
  const DBSYNC_HANDLE handle,
  const cJSON* json_raw) {
  auto ret_val { 1l };
  if (nullptr != json_raw) {
    const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_Print(json_raw)};
    ret_val = DBSyncImplementation::getInstance().insertBulkData(handle, spJsonBytes.get());
  }
  return ret_val;
}

int dbsync_update_with_snapshot(
    const DBSYNC_HANDLE handle,
    const cJSON* json_snapshot,
    cJSON** json_return_modifications)
{
  auto ret_val { false };
  if (nullptr != json_snapshot) {
    std::string result;
    const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(json_snapshot)};
    ret_val = DBSyncImplementation::getInstance().updateSnapshotData(handle, spJsonBytes.get(), result);
    *json_return_modifications = cJSON_Parse(result.c_str());
  }
  return ret_val;
}

int dbsync_update_with_snapshot_cb(
    const DBSYNC_HANDLE handle,
    const cJSON* json_snapshot,
    void* callback)
{
  auto ret_val { 0l };
  if (nullptr != json_snapshot) {
    const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(json_snapshot)};
    ret_val = DBSyncImplementation::getInstance().updateSnapshotData(handle, spJsonBytes.get(), callback);
  }
  return ret_val;
}

void dbsync_teardown(void) {
  DBSyncImplementation::getInstance().release();
}

void dbsync_free_result(
    cJSON** json_result){
  
  if (nullptr != *json_result) {
    cJSON_Delete(*json_result);
  }
}

#ifdef __cplusplus
}
#endif
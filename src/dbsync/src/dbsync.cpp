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

unsigned long long dbsync_initialize(
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

int dbsync_insert_data(
  const unsigned long long handle,
  const cJSON* json_raw) {
  auto ret_val { 1l };
  if (nullptr != json_raw) {
    char* json_raw_bytes = cJSON_Print(json_raw);
    ret_val = DBSyncImplementation::getInstance().InsertBulkData(handle, json_raw_bytes);
    cJSON_free(json_raw_bytes);
  }
  return ret_val;
}

int dbsync_update_with_snapshot(
    const unsigned long long handle,
    const cJSON* json_snapshot,
    cJSON** json_return_modifications)
{
  auto ret_val { false };
  if (nullptr != json_snapshot) {
    std::string result;
    char* json_raw_bytes = cJSON_PrintUnformatted(json_snapshot);
    ret_val = DBSyncImplementation::getInstance().UpdateSnapshotData(handle, json_raw_bytes, result);
    cJSON_free(json_raw_bytes);
    
    *json_return_modifications = cJSON_Parse(result.c_str());
  }
  return ret_val;
}

int dbsync_update_with_snapshot_cb(
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

void dbsync_teardown(void) {
  if(!DBSyncImplementation::getInstance().Release()) {
    std::cout << "Error when release DBSyncImplementation" << std::endl;
  }
}

#ifdef __cplusplus
}
#endif
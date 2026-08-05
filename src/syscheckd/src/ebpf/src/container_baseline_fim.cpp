/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Option A: container FIM baseline through the host event flow (spike #37532).
 *
 * For each discovered container:
 *  1. Collect raw file_entry dbsync rows via cbaseline_run_fim_dbsync.
 *  2. Stamp a deterministic checksum (SHA1 of the row dump) onto each row.
 *  3. Open a per-container scoped fim_db_transaction_start so change detection
 *     is isolated to that container's rows (container_id = <id>).
 *  4. Sync every row via fim_db_transaction_sync_row_json — DBSync computes
 *     INSERTED/MODIFIED/DELETED and fires container_txn_callback.
 *  5. container_txn_callback calls fim_persist_baseline_row which normalises
 *     the flat dbsync row to the stateful ECS schema and persists it.
 *  6. After all active containers are processed, clean up stale containers
 *     (present in DB but absent from the current baseline) by running an empty
 *     scoped txn which marks and emits DELETED events for all their rows.
 */

#include "container_baseline_fim.h"
#include "container_baseline.h"
#include "container_baseline_fim_bridge.h"
#include "db.h"
#include "fimCommonDefs.h"

#include <json.hpp>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

struct ContainerTxnCtx {
    std::string container_id;
};

// C-compatible txn callback — called by DBSync for INSERTED / MODIFIED / DELETED.
void container_txn_callback(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data)
{
    if (!result_json || !user_data) return;
    auto* ctx = static_cast<ContainerTxnCtx*>(user_data);

    const cJSON* row_data = result_json;
    int op;

    switch (result_type) {
        case INSERTED:
            op = 0; // OPERATION_CREATE
            break;
        case MODIFIED:
            row_data = cJSON_GetObjectItem(result_json, "new");
            if (!row_data) return;
            op = 1; // OPERATION_MODIFY
            break;
        case DELETED:
            op = 2; // OPERATION_DELETE
            break;
        default:
            return;
    }

    const cJSON* path_json = cJSON_GetObjectItem(row_data, "path");
    if (!path_json || !cJSON_IsString(path_json)) return;

    const cJSON* version_json = cJSON_GetObjectItem(row_data, "version");
    const uint64_t version = version_json
        ? static_cast<uint64_t>(cJSON_GetNumberValue(version_json))
        : 1;

    const std::string id = ctx->container_id + ":" + cJSON_GetStringValue(path_json);

    char* row_str = cJSON_PrintUnformatted(row_data);
    if (!row_str) return;
    fim_persist_baseline_row(id.c_str(), op, "wazuh-states-fim-files", row_str, version);
    free(row_str);
}

// Wrapper passed as user_data for cbaseline_run_fim_dbsync.
struct DbsyncSinkCtx {
    std::map<std::string, std::vector<std::string>>* container_rows;
};

void dbsync_sink(const char* container_id, const char* /*table*/,
                 const char* row_json, void* user_data)
{
    if (!container_id || !row_json || !user_data) return;
    auto* sink_ctx = static_cast<DbsyncSinkCtx*>(user_data);

    auto row = nlohmann::json::parse(row_json, nullptr, false);
    if (row.is_discarded()) return;

    // Compute a stable checksum so DBSync can detect row-level changes between runs.
    const std::string dump = row.dump();
    char sha1[41] = {0};
    fim_compute_row_checksum(dump.c_str(), sha1);
    row["checksum"] = std::string(sha1);

    (*sink_ctx->container_rows)[container_id].push_back(row.dump());
}

// Open a scoped txn for `container_id`, sync all `rows`, process deletions.
void sync_container(const std::string& container_id,
                    const std::vector<std::string>& rows)
{
    nlohmann::json txn_json;
    txn_json["tables"] = nlohmann::json::array({"file_entry"});
    txn_json["scope"]  = {{"column", FIMDB_FILE_CONTAINER_ID_COLUMN},
                           {"value",  container_id}};
    const std::string txn_str = txn_json.dump();

    ContainerTxnCtx ctx{container_id};
    TXN_HANDLE txn = fim_db_transaction_start(txn_str.c_str(), container_txn_callback, &ctx);
    if (!txn) return;

    for (const auto& row_json : rows) {
        // Parsed back into a typed row (instead of synced as raw JSON) so this
        // goes through the same FileItem/fim_db_transaction_sync_row() path
        // host rows use. Fields match BuildFimFileDbsyncRow()'s shape
        // (baseline_rows.cpp) plus the checksum dbsync_sink() adds above.
        const auto row = nlohmann::json::parse(row_json, nullptr, false);
        if (row.is_discarded() || !row.is_object()) continue;

        const std::string path = row.value("path", "");
        const std::string permissions = row.value("permissions", "");
        const std::string attributes = row.value("attributes", "");
        const std::string uid = row.value("uid", "");
        const std::string gid = row.value("gid", "");
        const std::string owner = row.value("owner", "");
        const std::string group = row.value("group_", "");
        const std::string row_container_json = row.value("container_json", "");
        const std::string hash_md5 = row.value("hash_md5", "");
        const std::string hash_sha1 = row.value("hash_sha1", "");
        const std::string hash_sha256 = row.value("hash_sha256", "");
        const std::string checksum = row.value("checksum", "");

        fim_file_data data{};
        data.permissions = const_cast<char*>(permissions.c_str());
        data.attributes = const_cast<char*>(attributes.c_str());
        data.uid = const_cast<char*>(uid.c_str());
        data.gid = const_cast<char*>(gid.c_str());
        data.owner = const_cast<char*>(owner.c_str());
        data.group = const_cast<char*>(group.c_str());
        data.container_id = const_cast<char*>(container_id.c_str());
        data.container_json = const_cast<char*>(row_container_json.c_str());
        data.size = row.value<unsigned long long int>("size", 0);
        data.inode = row.value<unsigned long long int>("inode", 0);
        data.device = static_cast<unsigned long int>(row.value<unsigned long long int>("device", 0));
        data.mtime = static_cast<time_t>(row.value<int64_t>("mtime", 0));
        data.version = 1;
        if (!hash_md5.empty()) {
            std::snprintf(data.hash_md5, sizeof(data.hash_md5), "%s", hash_md5.c_str());
            std::snprintf(data.hash_sha1, sizeof(data.hash_sha1), "%s", hash_sha1.c_str());
            std::snprintf(data.hash_sha256, sizeof(data.hash_sha256), "%s", hash_sha256.c_str());
        }
        std::snprintf(data.checksum, sizeof(data.checksum), "%s", checksum.c_str());

        fim_entry entry{};
        entry.type = FIM_TYPE_FILE;
        entry.file_entry.path = const_cast<char*>(path.c_str());
        entry.file_entry.data = &data;

        fim_db_transaction_sync_row(txn, &entry);
    }

    fim_db_transaction_deleted_rows(txn, container_txn_callback, &ctx);
}

} // namespace

extern "C" void fim_run_container_baseline(void)
{
    cb_monitored_path_t* paths = nullptr;
    size_t path_count = 0;

    if (fim_collect_container_monitored_paths(&paths, &path_count) != 0) return;
    if (!paths || path_count == 0U) return;

    if (!fim_container_baseline_available(CB_DEFAULT_CONNECTOR_SOCKET_PATH)) {
        fim_free_container_monitored_paths(paths);
        return;
    }

    // Phase 1: collect rows grouped by container_id.
    std::map<std::string, std::vector<std::string>> container_rows;
    DbsyncSinkCtx sink_ctx{&container_rows};

    cbaseline_run_fim_dbsync(CB_DEFAULT_CONNECTOR_SOCKET_PATH,
                             paths,
                             static_cast<int>(path_count),
                             dbsync_sink,
                             &sink_ctx);

    fim_free_container_monitored_paths(paths);

    // Phase 2: per-container scoped txns — computes deltas, emits events.
    for (const auto& [container_id, rows] : container_rows) {
        sync_container(container_id, rows);
    }

    // Phase 3: stale container cleanup — containers still in DB but gone from
    // the current baseline get all their rows marked DELETED.
    cJSON* db_rows = fim_db_get_every_element("file_entry", "WHERE container_id != ''");
    if (db_rows && cJSON_IsArray(db_rows)) {
        std::set<std::string> db_container_ids;
        cJSON* db_row;
        cJSON_ArrayForEach(db_row, db_rows) {
            const cJSON* cid = cJSON_GetObjectItem(db_row, "container_id");
            if (cid && cJSON_IsString(cid) && cid->valuestring && cid->valuestring[0] != '\0') {
                db_container_ids.insert(cid->valuestring);
            }
        }
        cJSON_Delete(db_rows);

        for (const auto& stale_id : db_container_ids) {
            if (container_rows.find(stale_id) == container_rows.end()) {
                sync_container(stale_id, {}); // empty rows → all existing rows become DELETED
            }
        }
    } else {
        cJSON_Delete(db_rows);
    }

    fim_report_container_baseline_result(static_cast<int>(container_rows.size()));
}

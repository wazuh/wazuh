/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_live_fim.h"
#include "container_baseline_fim_bridge.h"
#include "container_instances_client.hpp"
#include "db.h"
#include "fimCommonDefs.h"
#include "md5_sha1_sha256_op.h"
#include "syscheck.h"

// Neither header has an extern "C" guard of its own (both are included only
// from .c translation units elsewhere) -- wrap them here so
// fim_attributes_json(), fim_calculate_dbsync_difference(), and
// get_iso8601_utc_time() get C linkage, matching how their definitions in
// file.c/events.c/time_op.c are actually compiled.
extern "C"
{
#include "file.h"
#include "time_op.h"
}

#include <json.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace {

// Best-effort mapping of container_instances' resolved enrichment record
// (a ContainerRecord-shaped JSON: containerId/containerName/image/...) onto
// the {"container": {...}, "kubernetes": {...}} shape
// container_baseline_fim_bridge.c's normalize_container_fim_row() expects in
// a row's container_json column. This duplicates
// container_baseline_impl::BuildContainerContextJson()'s job in miniature
// because that function is a private symbol of a separate shared library
// (container_baseline_impl is linked PRIVATE into container_baseline.so, not
// re-exported) — unifying the two into one shared helper is a reasonable
// follow-up once both call sites are stable, not attempted here.
//
// Field names are inferred from container_record.hpp's C++ struct and are
// not independently verified against container_instances' wire format;
// treat as a best-effort mapping to be confirmed against that module.
std::string build_container_json(const std::string& container_id, const nlohmann::json& record)
{
    nlohmann::json out;
    nlohmann::json container;

    container["id"] = container_id;
    if (record.contains("containerName") && record["containerName"].is_string())
    {
        container["name"] = record["containerName"];
    }
    if (record.contains("image") && record["image"].is_string())
    {
        container["image"] = {{"name", record["image"]}};
        if (record.contains("imageDigest") && record["imageDigest"].is_string())
        {
            container["image"]["digest"] = record["imageDigest"];
        }
    }
    if (record.contains("labels") && record["labels"].is_object())
    {
        container["labels"] = record["labels"];
    }
    out["container"] = container;

    const bool is_kubernetes = record.contains("podName") && record["podName"].is_string() &&
                               !record["podName"].get<std::string>().empty();
    if (is_kubernetes)
    {
        nlohmann::json kubernetes;
        kubernetes["pod"] = {{"name", record.value("podName", "")}, {"uid", record.value("podUid", "")}};
        kubernetes["namespace"] = record.value("podNamespace", "");
        if (record.contains("nodeName") && record["nodeName"].is_string())
        {
            kubernetes["node"] = {{"name", record["nodeName"]}};
        }
        out["kubernetes"] = kubernetes;
    }

    return out.dump();
}

// Builds and sends the stateless FIM alert (the one carrying `changed_fields`)
// that neither fim_persist_baseline_row() nor validate_and_persist_fim_event()
// ever produce on their own -- they only ever build the stateful/synced
// document. This mirrors file.c's transaction_callback(), the host FIM
// equivalent: same event envelope, same fim_attributes_json()/
// fim_calculate_dbsync_difference() calls, so a container file alert looks
// like a normal FIM alert with container/kubernetes enrichment attached.
//
// `row_data` is the current (or, for "deleted", the last-known) flat row;
// `old_data` is non-null only for "modified" and holds just the changed
// columns' previous values -- dbsync's own "old" object (see
// SQLiteDBEngine::getRowDiff(), which fills "old" with only-what-changed and
// "new"/the top-level row with every column, so fim_attributes_json() always
// sees a complete row here).
//
// Container rows have no fim_file_data struct (see the primary-key section
// of requirements-analysis.md) so this always calls fim_attributes_json()
// in its JSON-only mode (data == NULL) -- unlike the host path, which mostly
// uses the typed struct and only falls back to JSON for orphaned deletes.
//
// Always sends, regardless of notify_scan: unlike host FIM's scheduled scan,
// there is no "first full scan" for this live path to suppress -- the
// container's own one-shot initial population is a separate module
// (container_baseline) that never calls this function.
void send_container_stateless_event(const char* event_type, const cJSON* row_data, const cJSON* old_data)
{
    const cJSON* path_json = cJSON_GetObjectItem(row_data, "path");
    if (!path_json || !cJSON_IsString(path_json))
    {
        return;
    }
    const char* path = cJSON_GetStringValue(path_json);

    directory_t* config = fim_configuration_directory(path, true, syscheck.directories);
    if (!config)
    {
        return;
    }

    cJSON* changed_attributes = nullptr;
    cJSON* old_attributes = nullptr;
    if (old_data)
    {
        changed_attributes = cJSON_CreateArray();
        old_attributes = cJSON_CreateObject();
        fim_calculate_dbsync_difference(config, old_data, changed_attributes, old_attributes);
        if (cJSON_GetArraySize(changed_attributes) == 0)
        {
            // Nothing the configured checks care about actually changed (e.g. only
            // internal bookkeeping columns did) -- matches file.c's own
            // FIM_EMPTY_CHANGED_ATTRIBUTES early-exit, avoiding a no-op alert.
            cJSON_Delete(changed_attributes);
            cJSON_Delete(old_attributes);
            return;
        }
    }

    cJSON* stateless_event = cJSON_CreateObject();
    cJSON_AddStringToObject(stateless_event, "collector", "file");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    char iso_time[32];
    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", event_type);

    // A deleted file has no live attributes left to report -- mirrors file.c's
    // handle_orphaned_delete(), which also sends a path/mode-only stateless event.
    cJSON* file_stateless =
        (strcmp(event_type, "deleted") == 0) ? cJSON_CreateObject() : fim_attributes_json(row_data, nullptr, config);
    cJSON_AddItemToObject(data, "file", file_stateless);
    cJSON_AddStringToObject(file_stateless, "path", path);
    cJSON_AddStringToObject(file_stateless, "mode", "whodata");
    if (config->tag)
    {
        cJSON_AddStringToObject(file_stateless, "tags", config->tag);
    }

    if (changed_attributes)
    {
        cJSON_AddItemToObject(file_stateless, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);
    }

    // Lift container/kubernetes enrichment onto the alert at the same level
    // container_baseline_fim_bridge.c's normalize_container_fim_row() already
    // uses for the stateful document (top-level blocks, siblings of "file"),
    // rather than inventing a new placement convention for the stateless side.
    const cJSON* container_json_item = cJSON_GetObjectItem(row_data, "container_json");
    if (container_json_item && cJSON_IsString(container_json_item) && container_json_item->valuestring &&
        container_json_item->valuestring[0])
    {
        cJSON* ctx = cJSON_Parse(container_json_item->valuestring);
        if (ctx)
        {
            cJSON* container_block = cJSON_DetachItemFromObject(ctx, "container");
            if (container_block)
            {
                cJSON_AddItemToObject(data, "container", container_block);
            }
            cJSON* kubernetes_block = cJSON_DetachItemFromObject(ctx, "kubernetes");
            if (kubernetes_block)
            {
                cJSON_AddItemToObject(data, "kubernetes", kubernetes_block);
            }
            cJSON_Delete(ctx);
        }
    }

    send_syscheck_msg(stateless_event);
    cJSON_Delete(stateless_event);
}

// Single-row upsert: opens a transaction scoped to this one container
// (mirroring container_baseline_fim.cpp's sync_container()) but — unlike the
// baseline — never calls fim_db_transaction_deleted_rows(). That call is
// what turns "any row in scope not touched by this transaction" into a
// DELETE; skipping it means this single-row sync can only ever
// INSERT/MODIFY the one row it submits, leaving every other file already
// tracked for this container untouched. Reserving the full scope+
// deleted_rows sweep for whole-container reconciliation (baseline runs,
// container removal) is intentional, not an oversight.
void upsert_container_file_row(const std::string& container_id, const std::string& row_json)
{
    nlohmann::json txn_json;
    txn_json["tables"] = nlohmann::json::array({"file_entry"});
    txn_json["scope"] = {{"column", FIMDB_FILE_CONTAINER_ID_COLUMN}, {"value", container_id}};
    const std::string txn_str = txn_json.dump();

    // fim_persist_baseline_row() is reused as-is: despite the name, it only
    // normalizes a flat row + persists via validate_and_persist_fim_event(),
    // with no baseline-specific behavior — the same helper is the right fit
    // for a live single-row upsert.
    TXN_HANDLE txn = fim_db_transaction_start(txn_str.c_str(),
        [](ReturnTypeCallback result_type, const cJSON* result_json, void* /*user_data*/)
        {
            if (!result_json)
            {
                return;
            }

            const cJSON* row_data = result_json;
            const cJSON* old_data = nullptr;
            int operation;

            switch (result_type)
            {
                case INSERTED:
                    operation = 0; // OPERATION_CREATE
                    break;
                case MODIFIED:
                    row_data = cJSON_GetObjectItem(result_json, "new");
                    old_data = cJSON_GetObjectItem(result_json, "old");
                    if (!row_data)
                    {
                        return;
                    }
                    operation = 1; // OPERATION_MODIFY
                    break;
                default:
                    return;
            }

            const cJSON* path_json = cJSON_GetObjectItem(row_data, "path");
            const cJSON* cid_json = cJSON_GetObjectItem(row_data, "container_id");
            if (!path_json || !cJSON_IsString(path_json) || !cid_json || !cJSON_IsString(cid_json))
            {
                return;
            }

            send_container_stateless_event(result_type == INSERTED ? "added" : "modified", row_data, old_data);

            const std::string id = std::string(cJSON_GetStringValue(cid_json)) + ":" + cJSON_GetStringValue(path_json);
            char* row_str = cJSON_PrintUnformatted(row_data);
            if (!row_str)
            {
                return;
            }
            fim_persist_baseline_row(id.c_str(), operation, FIM_FILES_SYNC_INDEX, row_str, 1);
            free(row_str);
        },
        nullptr);

    if (!txn)
    {
        return;
    }

    fim_db_transaction_sync_row_json(txn, "file_entry", row_json.c_str());
}

void delete_container_file_row(const std::string& container_id, const std::string& path, const std::string& container_json)
{
    nlohmann::json row;
    row["container_id"] = container_id;
    row["path"] = path;
    row["container_json"] = container_json;

    const std::string id = container_id + ":" + path;
    const std::string row_str = row.dump();

    // Stateless "deleted" alert first, from the same flat JSON handed to
    // fim_persist_baseline_row() below -- once fim_db_container_file_delete()
    // removes the row, there is no diff-callback path left to build it from.
    cJSON* row_json = cJSON_Parse(row_str.c_str());
    if (row_json)
    {
        send_container_stateless_event("deleted", row_json, nullptr);
        cJSON_Delete(row_json);
    }

    // Persist the DELETE document — once fim_db_container_file_delete()
    // removes the row, there is no diff-callback path left to build it from.
    fim_persist_baseline_row(id.c_str(), 2 /* OPERATION_DELETE */, FIM_FILES_SYNC_INDEX, row_str.c_str(), 1);
    fim_db_container_file_delete(path.c_str(), container_id.c_str());
}

} // namespace

extern "C" void fim_handle_container_whodata_event(uint64_t cgroup_id,
                                                    uint32_t /*mnt_ns*/,
                                                    uint32_t pid,
                                                    const char* kernel_path,
                                                    uint64_t /*inode*/,
                                                    uint64_t /*dev*/)
{
    if (!syscheck.enable_synchronization || !kernel_path)
    {
        return;
    }

    const wazuh::container_instances_client::ContainerInstancesClient client(CB_DEFAULT_CONNECTOR_SOCKET_PATH);
    const auto lookup = client.resolveByCgroupId(cgroup_id);

    // Cold cache / module unavailable / not a container: drop. See
    // container_live_fim.h's doc comment for why this never falls back to
    // the host FIM path.
    if (lookup.status != wazuh::container_instances_client::LookupStatus::resolved)
    {
        return;
    }

    const auto record = nlohmann::json::parse(lookup.json, nullptr, false);
    if (record.is_discarded() || !record.is_object() || !record.contains("containerId") ||
        !record["containerId"].is_string())
    {
        return;
    }
    const std::string container_id = record["containerId"].get<std::string>();
    const std::string path(kernel_path);

    // Resolve the kernel-reported (writer's-mount-ns-view) path to a
    // host-openable path via the same /proc/<pid>/root translation the
    // #37532 baseline's rootfs_file_walker.cpp already relies on — the
    // kernel does the mount-namespace resolution for us, so there is no
    // OCI-mount/overlay math to reimplement here.
    //
    // Known limitation: if the pid has already exited by the time this
    // runs, there is no fallback to another live pid in the same container
    // (that requires container_baseline_impl's private
    // ResolvePidsForContainer(), not linkable from here — see the header
    // comment). The event is dropped in that case, a documented instance of
    // #37533's own "lifecycle races" open question.
    if (access(("/proc/" + std::to_string(pid)).c_str(), F_OK) != 0)
    {
        return;
    }

    const std::string host_path = "/proc/" + std::to_string(pid) + "/root" + path;
    const std::string container_json = build_container_json(container_id, record);

    struct stat st{};
    if (::lstat(host_path.c_str(), &st) != 0)
    {
        // Confirmed live pid, missing file: genuine delete.
        delete_container_file_row(container_id, path, container_json);
        return;
    }

    if (!S_ISREG(st.st_mode))
    {
        // Only regular files are tracked, matching FileBaselineRow's own
        // scope (symlinks/sockets/fifos/devices are skipped there too).
        return;
    }

    char permissions_buf[8];
    std::snprintf(permissions_buf, sizeof(permissions_buf), "0%o", static_cast<unsigned int>(st.st_mode & 07777));

    nlohmann::json row;
    row["container_id"] = container_id;
    row["container_json"] = container_json;
    row["path"] = path;
    row["permissions"] = permissions_buf;
    row["uid"] = std::to_string(st.st_uid);
    row["gid"] = std::to_string(st.st_gid);
    row["size"] = static_cast<uint64_t>(st.st_size);
    row["inode"] = static_cast<uint64_t>(st.st_ino);
    row["device"] = static_cast<uint64_t>(st.st_dev);
    row["mtime"] = static_cast<int64_t>(st.st_mtime);
    row["version"] = 1;

    if (static_cast<size_t>(st.st_size) < syscheck.file_max_size)
    {
        os_md5 md5 = {0};
        os_sha1 sha1 = {0};
        os_sha256 sha256 = {0};
        if (OS_MD5_SHA1_SHA256_File(host_path.c_str(), md5, sha1, sha256, OS_BINARY, syscheck.file_max_size) == 0)
        {
            row["hash_md5"] = md5;
            row["hash_sha1"] = sha1;
            row["hash_sha256"] = sha256;
        }
    }

    const std::string dump = row.dump();
    char checksum[41] = {0};
    fim_compute_row_checksum(dump.c_str(), checksum);
    row["checksum"] = checksum;

    upsert_container_file_row(container_id, row.dump());
}

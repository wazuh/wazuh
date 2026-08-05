/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// time_op.h is small and self-contained (<stdio.h>/<time.h>/<sys/time.h>
// only) but has no extern "C" guard of its own. Include it FIRST here,
// wrapped, so get_iso8601_utc_time() claims C linkage before anything else
// in this file's include chain can reach it unwrapped -- it otherwise
// arrives transitively via syscheck.h -> syscheck-config.h -> shared.h a few
// lines below. A real build on the wazuh_manager VM caught this exact
// ordering trap: with shared.h's unwrapped #include "time_op.h" processed
// first, this header's own include-guard made a *later* wrapped
// #include "time_op.h" a silent no-op, leaving get_iso8601_utc_time() with
// C++ linkage and a mangled undefined reference at final link time.
//
// file.h (which declares the other three C functions this file needs) can't
// get the same treatment: it pulls in syscheck.h's entire chain, which
// eventually reaches real C++ standard headers (e.g. <atomic>) -- wrapping
// that whole chain in extern "C" doesn't compile (C++ templates cannot have
// C linkage). Those three are hand-forward-declared instead, once
// directory_t/fim_file_data/cJSON are already visible from the normal
// #include "syscheck.h" below -- see the second extern "C" block.
// debug_op.h (mdebug2() and friends) has the same unwrapped-transitively
// problem and is just as safe to wrap alone (only <stdarg.h>/<cJSON.h>).
extern "C"
{
#include "time_op.h"
#include "debug_op.h"
}

#include "container_live_fim.h"
#include "container_baseline_fim_bridge.h"
#include "container_instances_client.hpp"
#include "db.h"
#include "fimCommonDefs.h"
#include "md5_sha1_sha256_op.h"
#include "syscheck.h"

// Declared here with C linkage rather than via #include "file.h" (see the
// comment above) -- signatures copied as-is from src/file/file.h.
extern "C"
{
cJSON* fim_attributes_json(const cJSON* dbsync_event, const fim_file_data* data, const directory_t* configuration);
void fim_calculate_dbsync_difference(const directory_t* configuration,
                                      const cJSON* old_data,
                                      cJSON* changed_attributes,
                                      cJSON* old_attributes);
directory_t* fim_configuration_directory(const char* key, bool notify_not_found, const OSList* directories_list);
}

#include <json.hpp>

// ResolvePidsForContainer() (PID-liveness fallback, see
// container-fim-syscollector-test-plan-and-results.md finding #3) and
// WalkContainerPath() (the lazy per-container catch-up baseline below, see
// startup-race-solutions-and-edge-cases.md's Option C) are real, exported
// C++ symbols of libcontainer_baseline.so (confirmed via `nm -D` on a built
// agent) that live under container_baseline_impl/, not container_baseline's
// public include/. Included directly here (CMakeLists.txt adds that path)
// rather than hand-declaring them: ResolvePidsForContainer's plain
// vector<pid_t>/string signature would have been safe to hand-declare (as
// it originally was), but WalkContainerPath returns FileBaselineRow/
// WalkResult *by value* -- a hand-duplicated struct layout that silently
// drifted from the real one would corrupt memory instead of failing to
// link, so both are pulled from the real headers instead.
#include "pid_resolver.hpp"
#include "rootfs_file_walker.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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
// `data` is the *nested* "data" object from a resolveByCgroupId() reply
// ({"status":"resolved","data":{...}} -- see recordToJson() in
// container_instances/ci_impl/src/ipc/wire_protocol.hpp for the authoritative
// shape), not the reply's top level. Field names are the snake_case ones
// recordToJson() actually serializes (container_id/container_name/image/
// image_digest/labels/pod_name/pod_uid/namespace/node_name/runtime) --
// verified against wire_protocol.hpp directly, not inferred, after the
// original camelCase/top-level assumptions here turned out to never match
// (see container-fim-syscollector-test-plan-and-results.md finding #3: every
// live-path event was silently dropped because of exactly this mismatch).
std::string build_container_json(const std::string& container_id, const nlohmann::json& data)
{
    nlohmann::json out;
    nlohmann::json container;

    container["id"] = container_id;
    if (data.contains("container_name") && data["container_name"].is_string())
    {
        container["name"] = data["container_name"];
    }
    if (data.contains("image") && data["image"].is_string())
    {
        container["image"] = {{"name", data["image"]}};
        if (data.contains("image_digest") && data["image_digest"].is_string())
        {
            container["image"]["digest"] = data["image_digest"];
        }
    }
    if (data.contains("labels") && data["labels"].is_object())
    {
        container["labels"] = data["labels"];
    }
    out["container"] = container;

    const bool is_kubernetes = data.value("runtime", "") == "kubernetes";
    if (is_kubernetes)
    {
        nlohmann::json kubernetes;
        kubernetes["pod"] = {{"name", data.value("pod_name", "")}, {"uid", data.value("pod_uid", "")}};
        kubernetes["namespace"] = data.value("namespace", "");
        if (data.contains("node_name") && data["node_name"].is_string())
        {
            kubernetes["node"] = {{"name", data["node_name"]}};
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
void upsert_container_file_row(const std::string& container_id, const fim_entry* entry)
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

    fim_db_transaction_sync_row(txn, entry);
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

bool container_has_existing_rows(const std::string& container_id)
{
    const std::string filter = "WHERE container_id = '" + container_id + "' LIMIT 1";
    cJSON* rows = fim_db_get_every_element("file_entry", filter.c_str());
    const bool has_rows = rows && cJSON_IsArray(rows) && cJSON_GetArraySize(rows) > 0;
    if (rows)
    {
        cJSON_Delete(rows);
    }
    return has_rows;
}

// Shared by catch_up_container_baseline()'s sync-row call and its
// finalizing fim_db_transaction_deleted_rows() call below (see there for why
// the latter is required) -- mirrors container_baseline_fim.cpp's own
// container_txn_callback(), private to that translation unit.
void catch_up_txn_callback(ReturnTypeCallback result_type, const cJSON* result_json, void* /*user_data*/)
{
    if (!result_json)
    {
        return;
    }

    const cJSON* row_data = result_json;
    int operation;

    switch (result_type)
    {
        case INSERTED:
            operation = 0; // OPERATION_CREATE
            break;
        case MODIFIED:
            row_data = cJSON_GetObjectItem(result_json, "new");
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

    const std::string id = std::string(cJSON_GetStringValue(cid_json)) + ":" + cJSON_GetStringValue(path_json);
    char* row_str = cJSON_PrintUnformatted(row_data);
    if (!row_str)
    {
        return;
    }
    fim_persist_baseline_row(id.c_str(), operation, FIM_FILES_SYNC_INDEX, row_str, 1);
    free(row_str);
}

// Lazy per-container catch-up baseline (startup-race-solutions-and-edge-cases.md,
// Option C): when the live path first resolves a container that has zero
// existing file_entry rows -- because FIM's one-shot startup baseline missed
// it (a container_instances connector was still warming up, #37533's finding
// #2) or because the container started after the agent did -- walk its
// configured container-tagged directories once, the same way a real baseline
// pass would have, so pre-existing files aren't permanently invisible just
// because no write ever happens to touch them. Persists rows via
// fim_persist_baseline_row() directly, with no stateless alert: a file that
// already existed before this agent noticed the container isn't a "change"
// worth alerting on, matching the real baseline's own behavior.
void catch_up_container_baseline(const std::string& container_id, const std::string& container_json, pid_t pid)
{
    cb_monitored_path_t* paths = nullptr;
    size_t path_count = 0;
    if (fim_collect_container_monitored_paths(&paths, &path_count) != 0 || !paths || path_count == 0U)
    {
        if (paths)
        {
            fim_free_container_monitored_paths(paths);
        }
        return;
    }

    // Holds each row's strings by value so the fim_file_data/fim_entry built
    // from them further down (raw pointers into these strings) stays valid --
    // built fresh from each entry immediately before its own sync call, never
    // stored itself.
    struct PreparedRow
    {
        std::string path, permissions, uid, gid, owner, group;
        std::string hash_md5, hash_sha1, hash_sha256, checksum;
        uint64_t size{0}, inode{0}, device{0};
        int64_t mtime{0};
    };
    std::vector<PreparedRow> rows;
    for (size_t i = 0; i < path_count; ++i)
    {
        const auto walk = wazuh::container_baseline::WalkContainerPath(
            pid, paths[i].internal_path, paths[i].recursion_level, paths[i].max_files, paths[i].max_hash_bytes);

        for (const auto& row : walk.rows)
        {
            PreparedRow prepared;
            prepared.path = row.path;
            prepared.permissions = row.permissions;
            prepared.uid = row.uid;
            prepared.gid = row.gid;
            prepared.owner = row.owner;
            prepared.group = row.group;
            prepared.size = row.size;
            prepared.inode = row.inode;
            prepared.device = row.device;
            prepared.mtime = row.mtime;
            if (!row.hash_md5.empty())
            {
                prepared.hash_md5 = row.hash_md5;
                prepared.hash_sha1 = row.hash_sha1;
                prepared.hash_sha256 = row.hash_sha256;
            }

            // file_entry.checksum is NOT NULL -- matches the single-event row
            // built in fim_handle_container_whodata_event() and
            // container_baseline_fim.cpp's own dbsync_sink(), both of which
            // compute this the same way (sha1 of the row dump so far) before
            // adding it. Missed on an earlier pass of this function; without
            // it, most rows in a multi-row transaction like this one failed
            // to persist even though the sync call itself never reported an
            // error. Computed over the same logical field set as before the
            // switch to FileItem below, so existing rows' checksums stay
            // comparable.
            nlohmann::json checksum_input;
            checksum_input["container_id"] = container_id;
            checksum_input["container_json"] = container_json;
            checksum_input["path"] = prepared.path;
            checksum_input["permissions"] = prepared.permissions;
            checksum_input["uid"] = prepared.uid;
            checksum_input["gid"] = prepared.gid;
            checksum_input["size"] = prepared.size;
            checksum_input["inode"] = prepared.inode;
            checksum_input["device"] = prepared.device;
            checksum_input["mtime"] = prepared.mtime;
            checksum_input["version"] = 1;
            if (!prepared.hash_md5.empty())
            {
                checksum_input["hash_md5"] = prepared.hash_md5;
                checksum_input["hash_sha1"] = prepared.hash_sha1;
                checksum_input["hash_sha256"] = prepared.hash_sha256;
            }
            char row_checksum[41] = {0};
            fim_compute_row_checksum(checksum_input.dump().c_str(), row_checksum);
            prepared.checksum = row_checksum;

            rows.push_back(std::move(prepared));
        }
    }
    fim_free_container_monitored_paths(paths);

    mdebug2("catch_up_container_baseline: container_id=%s walked %zu file(s) across %zu monitored path(s)",
            container_id.c_str(), rows.size(), path_count);

    if (rows.empty())
    {
        return;
    }

    // Scoped, non-alerting persist -- deliberately mirrors
    // container_baseline_fim.cpp's own sync_container()/container_txn_callback
    // (private to that translation unit, so not reused directly) rather than
    // upsert_container_file_row() above, which exists specifically to alert.
    nlohmann::json txn_json;
    txn_json["tables"] = nlohmann::json::array({"file_entry"});
    txn_json["scope"] = {{"column", FIMDB_FILE_CONTAINER_ID_COLUMN}, {"value", container_id}};
    const std::string txn_str = txn_json.dump();

    TXN_HANDLE txn = fim_db_transaction_start(txn_str.c_str(), catch_up_txn_callback, nullptr);
    if (!txn)
    {
        return;
    }

    for (const auto& row : rows)
    {
        fim_file_data data{};
        data.permissions = const_cast<char*>(row.permissions.c_str());
        data.attributes = const_cast<char*>("");
        data.uid = const_cast<char*>(row.uid.c_str());
        data.gid = const_cast<char*>(row.gid.c_str());
        data.owner = const_cast<char*>(row.owner.c_str());
        data.group = const_cast<char*>(row.group.c_str());
        data.container_id = const_cast<char*>(container_id.c_str());
        data.container_json = const_cast<char*>(container_json.c_str());
        data.size = row.size;
        data.inode = row.inode;
        data.device = static_cast<unsigned long int>(row.device);
        data.mtime = static_cast<time_t>(row.mtime);
        data.version = 1;
        if (!row.hash_md5.empty())
        {
            std::snprintf(data.hash_md5, sizeof(data.hash_md5), "%s", row.hash_md5.c_str());
            std::snprintf(data.hash_sha1, sizeof(data.hash_sha1), "%s", row.hash_sha1.c_str());
            std::snprintf(data.hash_sha256, sizeof(data.hash_sha256), "%s", row.hash_sha256.c_str());
        }
        std::snprintf(data.checksum, sizeof(data.checksum), "%s", row.checksum.c_str());

        fim_entry entry{};
        entry.type = FIM_TYPE_FILE;
        entry.file_entry.path = const_cast<char*>(row.path.c_str());
        entry.file_entry.data = &data;

        fim_db_transaction_sync_row(txn, &entry);
    }

    // Required to actually flush/commit the synced rows -- confirmed on real
    // hardware: without this call, a multi-row transaction like this one
    // (unlike upsert_container_file_row()'s single-row case, which doesn't
    // need it) only persisted 1-2 of several hundred synced rows, the rest
    // silently lost. Safe to call here even though this function is never
    // used on a container with pre-existing rows (container_has_existing_rows()
    // gates every call) -- there is nothing already in scope for it to
    // spuriously mark DELETED.
    fim_db_transaction_deleted_rows(txn, catch_up_txn_callback, nullptr);
}

// Runs synchronously, on the caller's own thread, deliberately -- NOT on a
// detached thread. `fim_handle_container_whodata_event()` (the only caller)
// itself runs on a single dedicated consumer thread
// (ebpf_pop_container_events), never concurrently with itself, so there is
// no *cross-thread* race to worry about here; there would be one if this ran
// concurrently with the caller's own upsert_container_file_row() for the
// same triggering file, both opening a scoped file_entry transaction for the
// same container_id from different threads at once -- confirmed on real
// hardware to actually happen: an async version of this (detached thread +
// mutex-guarded de-dup set) walked several hundred files correctly but only
// 2 ended up persisted, evidently lost to exactly that kind of transaction
// overlap. Only paid once per container's first sighting (gated by
// container_has_existing_rows()), so a brief pause on the consumer thread
// here is an acceptable trade for correctness.
void maybe_catch_up_container_baseline(const std::string& container_id, const std::string& container_json, pid_t pid)
{
    if (container_has_existing_rows(container_id))
    {
        return;
    }

    mdebug2("maybe_catch_up_container_baseline: container_id=%s has no existing rows -- starting catch-up walk",
            container_id.c_str());

    catch_up_container_baseline(container_id, container_json, pid);
}

} // namespace

namespace
{
// Debug-only: names LookupStatus for the trace log below. Not used for control flow.
const char* lookup_status_name(wazuh::container_instances_client::LookupStatus status)
{
    switch (status)
    {
        case wazuh::container_instances_client::LookupStatus::resolved:     return "resolved";
        case wazuh::container_instances_client::LookupStatus::pending:      return "pending";
        case wazuh::container_instances_client::LookupStatus::notContainer: return "notContainer";
        case wazuh::container_instances_client::LookupStatus::unavailable:  return "unavailable";
    }
    return "unknown";
}
} // namespace

extern "C" void fim_handle_container_whodata_event(uint64_t cgroup_id,
                                                    uint32_t /*mnt_ns*/,
                                                    uint32_t pid,
                                                    const char* kernel_path,
                                                    uint64_t /*inode*/,
                                                    uint64_t /*dev*/)
{
    // TEMPORARY instrumentation added to root-cause #37533's "live path never
    // produces a row" finding (see container-fim-syscollector-test-plan-and-results.md) --
    // remove once that investigation is closed.
    mdebug2("fim_handle_container_whodata_event: cgroup_id=%llu pid=%u path=%s",
            (unsigned long long)cgroup_id, pid, kernel_path ? kernel_path : "(null)");

    if (!syscheck.enable_synchronization || !kernel_path)
    {
        mdebug2("fim_handle_container_whodata_event: dropped -- enable_synchronization=%d kernel_path=%s",
                syscheck.enable_synchronization, kernel_path ? "set" : "null");
        return;
    }

    const wazuh::container_instances_client::ContainerInstancesClient client(CB_DEFAULT_CONNECTOR_SOCKET_PATH);
    const auto lookup = client.resolveByCgroupId(cgroup_id);

    mdebug2("fim_handle_container_whodata_event: resolveByCgroupId(%llu) status=%s",
            (unsigned long long)cgroup_id, lookup_status_name(lookup.status));

    // Cold cache / module unavailable / not a container: drop. See
    // container_live_fim.h's doc comment for why this never falls back to
    // the host FIM path.
    if (lookup.status != wazuh::container_instances_client::LookupStatus::resolved)
    {
        return;
    }

    // A "resolved" reply's shape is {"status":"resolved","data":{"container_id":...,
    // "container_name":...,...}} -- snake_case, nested under "data" (see
    // recordToJson() in container_instances/ci_impl/src/ipc/wire_protocol.hpp,
    // the authoritative serializer). The top-level, camelCase "containerId"
    // this used to look for never existed in a real reply, so every live-path
    // event was silently dropped here regardless of container or runtime --
    // see container-fim-syscollector-test-plan-and-results.md finding #3.
    const auto record = nlohmann::json::parse(lookup.json, nullptr, false);
    if (record.is_discarded() || !record.is_object())
    {
        mdebug2("fim_handle_container_whodata_event: dropped -- resolved reply is not valid JSON: %s",
                lookup.json.c_str());
        return;
    }
    const auto data_it = record.find("data");
    if (data_it == record.end() || !data_it->is_object() || !data_it->contains("container_id") ||
        !(*data_it)["container_id"].is_string())
    {
        mdebug2("fim_handle_container_whodata_event: dropped -- resolved reply missing/invalid data.container_id: %s",
                lookup.json.c_str());
        return;
    }
    const nlohmann::json& data = *data_it;
    const std::string container_id = data["container_id"].get<std::string>();
    const std::string path(kernel_path);

    // Resolve the kernel-reported (writer's-mount-ns-view) path to a
    // host-openable path via the same /proc/<pid>/root translation the
    // #37532 baseline's rootfs_file_walker.cpp already relies on — the
    // kernel does the mount-namespace resolution for us, so there is no
    // OCI-mount/overlay math to reimplement here.
    //
    // The pid the eBPF event reports is a snapshot of whichever process
    // triggered the hook -- for the extremely common case of a short-lived
    // writer (`sh -c 'echo ... > file'`, a package-manager postinst script, a
    // config-reload helper, ...) that process has usually already exited by
    // the time this runs on the container-event worker thread. Empirically
    // this was the dominant failure mode once the JSON-shape bug above was
    // fixed (see container-fim-syscollector-test-plan-and-results.md finding
    // #3) -- essentially every `docker exec` one-liner used to test this
    // tripped it. Any other live process in the same container shares the
    // same mount namespace, so falling back to ResolvePidsForContainer()
    // (already proven correct -- it's the same resolver the #37532 baseline
    // uses) is exactly as valid for /proc/<pid>/root purposes as the
    // original pid would have been.
    uint32_t resolved_pid = pid;
    if (access(("/proc/" + std::to_string(pid)).c_str(), F_OK) != 0)
    {
        mdebug2("fim_handle_container_whodata_event: pid %u no longer alive (container_id=%s path=%s) -- "
                "falling back to ResolvePidsForContainer()",
                pid, container_id.c_str(), path.c_str());

        const auto fallback_pids = wazuh::container_baseline::ResolvePidsForContainer(container_id);
        if (fallback_pids.empty())
        {
            mdebug2("fim_handle_container_whodata_event: dropped -- no live pid left for container_id=%s "
                    "(container likely gone)",
                    container_id.c_str());
            return;
        }
        resolved_pid = static_cast<uint32_t>(fallback_pids.front());
        mdebug2("fim_handle_container_whodata_event: using fallback pid=%u for container_id=%s",
                resolved_pid, container_id.c_str());
    }

    mdebug2("fim_handle_container_whodata_event: resolved container_id=%s path=%s pid=%u -- proceeding to stat/persist",
            container_id.c_str(), path.c_str(), resolved_pid);

    const std::string host_path = "/proc/" + std::to_string(resolved_pid) + "/root" + path;
    const std::string container_json = build_container_json(container_id, data);

    maybe_catch_up_container_baseline(container_id, container_json, static_cast<pid_t>(resolved_pid));

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

    const std::string uid_str = std::to_string(st.st_uid);
    const std::string gid_str = std::to_string(st.st_gid);

    os_md5 md5 = {0};
    os_sha1 sha1 = {0};
    os_sha256 sha256 = {0};
    bool have_hashes = false;
    if (static_cast<size_t>(st.st_size) < syscheck.file_max_size)
    {
        have_hashes = (OS_MD5_SHA1_SHA256_File(host_path.c_str(), md5, sha1, sha256, OS_BINARY, syscheck.file_max_size) == 0);
    }

    // Checksum computed over the same logical field set this row has always
    // used (container_id/container_json/path/permissions/uid/gid/size/inode/
    // device/mtime/version/hashes) -- unchanged by the switch to FileItem
    // below, so pre-existing rows' checksums remain comparable.
    nlohmann::json checksum_input;
    checksum_input["container_id"] = container_id;
    checksum_input["container_json"] = container_json;
    checksum_input["path"] = path;
    checksum_input["permissions"] = permissions_buf;
    checksum_input["uid"] = uid_str;
    checksum_input["gid"] = gid_str;
    checksum_input["size"] = static_cast<uint64_t>(st.st_size);
    checksum_input["inode"] = static_cast<uint64_t>(st.st_ino);
    checksum_input["device"] = static_cast<uint64_t>(st.st_dev);
    checksum_input["mtime"] = static_cast<int64_t>(st.st_mtime);
    checksum_input["version"] = 1;
    if (have_hashes)
    {
        checksum_input["hash_md5"] = md5;
        checksum_input["hash_sha1"] = sha1;
        checksum_input["hash_sha256"] = sha256;
    }

    char checksum[41] = {0};
    fim_compute_row_checksum(checksum_input.dump().c_str(), checksum);

    // Typed row instead of a hand-built JSON string, so this goes through the
    // same FileItem/fim_db_transaction_sync_row() path host rows use (also
    // closes the drift where this row used to omit attributes/owner/group
    // entirely and skip FileItem's string normalization).
    // Named file_data, not data: an outer `const nlohmann::json& data` is
    // already in scope in this function (the resolveByCgroupId() enrichment
    // record) and must not be shadowed.
    fim_file_data file_data{};
    file_data.permissions = permissions_buf;
    file_data.attributes = const_cast<char*>("");
    file_data.uid = const_cast<char*>(uid_str.c_str());
    file_data.gid = const_cast<char*>(gid_str.c_str());
    file_data.owner = const_cast<char*>("");
    file_data.group = const_cast<char*>("");
    file_data.container_id = const_cast<char*>(container_id.c_str());
    file_data.container_json = const_cast<char*>(container_json.c_str());
    file_data.size = static_cast<unsigned long long int>(st.st_size);
    file_data.inode = static_cast<unsigned long long int>(st.st_ino);
    file_data.device = static_cast<unsigned long int>(st.st_dev);
    file_data.mtime = static_cast<time_t>(st.st_mtime);
    file_data.version = 1;
    if (have_hashes)
    {
        std::snprintf(file_data.hash_md5, sizeof(file_data.hash_md5), "%s", md5);
        std::snprintf(file_data.hash_sha1, sizeof(file_data.hash_sha1), "%s", sha1);
        std::snprintf(file_data.hash_sha256, sizeof(file_data.hash_sha256), "%s", sha256);
    }
    std::snprintf(file_data.checksum, sizeof(file_data.checksum), "%s", checksum);

    fim_entry entry{};
    entry.type = FIM_TYPE_FILE;
    entry.file_entry.path = const_cast<char*>(path.c_str());
    entry.file_entry.data = &file_data;

    upsert_container_file_row(container_id, &entry);
}

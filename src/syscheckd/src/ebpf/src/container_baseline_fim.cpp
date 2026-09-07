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
 * Rows are STREAMED into a per-container scoped DBSync transaction as they
 * arrive, rather than buffering the whole node's baseline in memory first: the
 * scanner emits a container's rows contiguously and then reports that
 * container's completeness, so the status callback is a natural container
 * boundary. Peak memory is therefore one row, not one node.
 *
 * Per container:
 *  1. First row opens a scoped fim_db_transaction_start (container_id = <id>),
 *     isolating change detection to that container's rows.
 *  2. Each row is checksummed and pushed with fim_db_transaction_sync_row_json.
 *  3. On the container's status callback the transaction is finalised:
 *       - complete scan -> fim_db_transaction_deleted_rows(), so rows that no
 *         longer exist become DELETED events;
 *       - INCOMPLETE scan -> plain close, deliberately skipping delete
 *         detection, because a capped/partial walk produced only a SUBSET of
 *         the container's files and absence must not be read as removal.
 *  4. After all containers, containers still in the DB but no longer KNOWN to
 *     container_instances (as opposed to merely stopped) have their rows aged
 *     out as DELETED.
 */

#include "container_baseline_fim.h"
#include "container_baseline.h"
#include "container_baseline_fim_bridge.h"
#include "container_event_drain.hpp"
#include "db.h"
#include "fimCommonDefs.h"

#include "commonDefs.h"

#include <json.hpp>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

/// Plain pass-through for a message that needs no formatting. Preferred over
/// the templates below by overload resolution, so a literal message skips
/// snprintf entirely — no 512-byte truncation, and no -Wformat-security
/// diagnostic for a "format" string that was never a format string.
void LogDebug(const char* msg)
{
    fim_container_baseline_log_debug(msg);
}

void LogError(const char* msg)
{
    fim_container_baseline_log_error(msg);
}

/// printf-style wrapper over the bridge's logging shims.
template <typename... Args>
void LogDebug(const char* fmt, Args... args)
{
    char buffer[512];
    std::snprintf(buffer, sizeof(buffer), fmt, args...);
    fim_container_baseline_log_debug(buffer);
}

template <typename... Args>
void LogError(const char* fmt, Args... args)
{
    char buffer[512];
    std::snprintf(buffer, sizeof(buffer), fmt, args...);
    fim_container_baseline_log_error(buffer);
}

struct ContainerTxnCtx {
    std::string container_id;
    /// cb_fim_origin_t: what the stateless alert reports as its "mode".
    int origin{CB_FIM_ORIGIN_SCAN};
};

// C-compatible txn callback — called by DBSync for INSERTED / MODIFIED / DELETED.
void container_txn_callback(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data)
{
    if (!result_json || !user_data) return;
    auto* ctx = static_cast<ContainerTxnCtx*>(user_data);

    const cJSON* row_data = result_json;
    const cJSON* old_data  = nullptr;
    Operation_t op;

    switch (result_type) {
        case INSERTED:
            op = OPERATION_CREATE;
            break;
        case MODIFIED:
            row_data = cJSON_GetObjectItem(result_json, "new");
            if (!row_data) return;
            // DBSync's "old" object carries exactly the columns that changed,
            // which is what the alert's changed_fields is derived from.
            old_data = cJSON_GetObjectItem(result_json, "old");
            op = OPERATION_MODIFY;
            break;
        case DELETED:
            op = OPERATION_DELETE;
            break;
        case DB_ERROR:
            LogDebug("Container FIM baseline: DBSync reported an error for container '%s'.",
                    ctx->container_id.c_str());
            return;
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

    // The alert first, then the stateful document — the same order file.c uses,
    // so a consumer reading both sees the notification no later than the state
    // it describes.
    fim_send_container_stateless_event(row_data, old_data, static_cast<int>(op), ctx->origin);

    char* row_str = cJSON_PrintUnformatted(row_data);
    if (!row_str) return;
    fim_persist_baseline_row(id.c_str(), static_cast<int>(op), "wazuh-states-fim-files", row_str, version);
    free(row_str);
}

/// Owns one container's scoped transaction for its lifetime.
///
/// The handle must be closed exactly once on every path, including an
/// exception: fim_db_transaction_deleted_rows() is what closes it in the happy
/// case, so a throw between start and that call previously leaked the handle
/// (there was no RAII and no catch anywhere in this file, so the exception also
/// escaped into syscheckd's main()).
class ScopedContainerTxn {
    public:
        ScopedContainerTxn(const std::string& container_id, int origin)
            : m_ctx{container_id, origin}
        {
            nlohmann::json txn_json;
            txn_json["tables"] = nlohmann::json::array({"file_entry"});
            txn_json["scope"]  = {{"column", FIMDB_FILE_CONTAINER_ID_COLUMN},
                                  {"value",  container_id}};
            const std::string txn_str = txn_json.dump();

            m_txn = fim_db_transaction_start(txn_str.c_str(), container_txn_callback, &m_ctx);

            if (!m_txn) {
                LogDebug("Container FIM baseline: could not start a transaction for container '%s'.",
                        container_id.c_str());
            }
        }

        ~ScopedContainerTxn()
        {
            // Only reached if finish() was not called (i.e. an exception unwound
            // past it); close without delete detection so a half-finished scan
            // cannot delete rows.
            if (m_txn) {
                fim_db_transaction_close(m_txn);
                m_txn = nullptr;
            }
        }

        ScopedContainerTxn(const ScopedContainerTxn&) = delete;
        ScopedContainerTxn& operator=(const ScopedContainerTxn&) = delete;

        [[nodiscard]] bool valid() const { return m_txn != nullptr; }

        void syncRow(const std::string& row_json)
        {
            if (!m_txn) return;

            if (fim_db_transaction_sync_row_json(m_txn, "file_entry", row_json.c_str()) != FIMDB_OK) {
                LogDebug("Container FIM baseline: failed to sync a row for container '%s'.",
                        m_ctx.container_id.c_str());
            }
        }

        /// @param detect_deletions false for an incomplete scan: the rows this
        ///        transaction did NOT refresh are missing because the walk was
        ///        capped or a path was absent, not because the files are gone.
        void finish(bool detect_deletions)
        {
            if (!m_txn) return;

            if (detect_deletions) {
                if (fim_db_transaction_deleted_rows(m_txn, container_txn_callback, &m_ctx) != FIMDB_OK) {
                    LogDebug("Container FIM baseline: delete detection failed for container '%s'.",
                            m_ctx.container_id.c_str());
                }
            } else {
                fim_db_transaction_close(m_txn);
            }

            m_txn = nullptr; // closed either way
        }

    private:
        ContainerTxnCtx m_ctx;
        TXN_HANDLE      m_txn{nullptr};
};

/// Streams the baseline into per-container transactions.
class BaselineDriver {
    public:
        /// `may_detect_deletions` is D15 (12-blocking-decisions.md) reaching the
        /// database. A path reconcile re-reads a handful of named files, so the
        /// rows it produces are a subset of the container's files BY DESIGN, not
        /// by accident — and delete detection over a subset deletes everything
        /// else the container owns. The whole-node and per-container walks pass
        /// true and stay gated on `partial` as before.
        ///
        /// `origin` (cb_fim_origin_t) is what this run's alerts report as their
        /// FIM "mode": a walk is a scan, a reconcile is whodata-driven.
        explicit BaselineDriver(bool may_detect_deletions = true, int origin = CB_FIM_ORIGIN_SCAN)
            : m_may_delete(may_detect_deletions)
            , m_origin(origin)
        {
        }

        void onRow(const char* container_id, const char* row_json)
        {
            if (!container_id || !row_json) return;

            beginContainer(container_id);
            if (!m_txn || !m_txn->valid()) return;

            auto row = nlohmann::json::parse(row_json, nullptr, false);
            if (row.is_discarded()) {
                LogDebug("Container FIM baseline: discarded a malformed row for container '%s'.",
                        container_id);
                ++m_malformed_rows;
                return;
            }

            // Stable checksum so DBSync can detect row-level changes between runs.
            //
            // The container-scope columns are excluded deliberately: container_id
            // is part of the row's key (the transaction is already scoped to it),
            // and container_json is a copy of the container's metadata blob. With
            // the blob inside the digest, editing one label changed the checksum
            // of every file row of that container and re-emitted the whole file
            // set as MODIFIED — a metadata edit reported as file changes.
            auto checksumInput = row;
            checksumInput.erase("container_id");
            checksumInput.erase("container_json");
            const std::string dump = checksumInput.dump();
            char sha1[41] = {0};
            fim_compute_row_checksum(dump.c_str(), sha1);
            row["checksum"] = std::string(sha1);

            m_txn->syncRow(row.dump());
            ++m_rows;
        }

        void onStatus(const char* container_id, bool partial)
        {
            if (!container_id) return;

            const std::string id{container_id};
            m_scanned.insert(id);

            // A complete scan that produced no rows still needs a transaction,
            // so previously-stored rows for this container age out as DELETED.
            beginContainer(id);

            if (partial) {
                LogDebug("Container FIM baseline: incomplete scan for container '%s' "
                        "(row cap reached, path absent, or namespace unreadable); "
                        "skipping delete detection to avoid false FIM deletions.",
                        container_id);
                ++m_partial;
            }

            finishCurrent(m_may_delete && !partial);
        }

        /// Containers still holding rows in the DB but no longer known to
        /// container_instances at all. A container that is merely STOPPED is
        /// still known and must be left alone — its rows are the state to
        /// resume diffing against when it restarts.
        void sweepStale(const std::set<std::string>& known)
        {
            finishCurrent(true);

            cJSON* db_ids = fim_db_get_distinct_container_ids("file_entry");
            if (!db_ids) {
                LogDebug("Container FIM baseline: could not read container ids from the database; "
                        "skipping the stale-container sweep.");
                return;
            }

            std::set<std::string> stale;

            if (cJSON_IsArray(db_ids)) {
                cJSON* item = nullptr;
                cJSON_ArrayForEach(item, db_ids) {
                    if (!cJSON_IsString(item) || !item->valuestring || item->valuestring[0] == '\0') continue;

                    const std::string id{item->valuestring};
                    if (known.find(id) == known.end()) {
                        stale.insert(id);
                    }
                }
            }
            cJSON_Delete(db_ids);

            for (const auto& id : stale) {
                LogDebug("Container FIM baseline: container '%s' is gone; ageing out its FIM rows.",
                        id.c_str());
                ScopedContainerTxn txn{id, m_origin};
                txn.finish(true); // no rows synced -> every stored row becomes DELETED
            }

            m_stale = stale.size();
        }

        [[nodiscard]] size_t rows() const { return m_rows; }
        [[nodiscard]] size_t scanned() const { return m_scanned.size(); }
        [[nodiscard]] size_t partial() const { return m_partial; }
        [[nodiscard]] size_t stale() const { return m_stale; }
        [[nodiscard]] size_t malformedRows() const { return m_malformed_rows; }

    private:
        void beginContainer(const std::string& container_id)
        {
            if (m_txn && m_current == container_id) return;

            // The scanner emits a container's rows contiguously, so a different
            // id means the previous container is done.
            finishCurrent(true);

            m_current = container_id;
            m_txn     = std::make_unique<ScopedContainerTxn>(container_id, m_origin);
        }

        void finishCurrent(bool detect_deletions)
        {
            if (!m_txn) return;

            m_txn->finish(detect_deletions);
            m_txn.reset();
            m_current.clear();
        }

        const bool                           m_may_delete{true};
        const int                            m_origin{CB_FIM_ORIGIN_SCAN};
        std::unique_ptr<ScopedContainerTxn> m_txn;
        std::string                          m_current;
        std::set<std::string>                m_scanned;
        size_t                               m_rows{0};
        size_t                               m_partial{0};
        size_t                               m_stale{0};
        size_t                               m_malformed_rows{0};
};

void dbsync_sink(const char* container_id, const char* /*table*/, const char* row_json, void* user_data)
{
    if (!user_data) return;
    static_cast<BaselineDriver*>(user_data)->onRow(container_id, row_json);
}

void status_sink(const char* container_id,
                 int         partial,
                 int         netns_host_scoped,
                 int         netns_unreadable,
                 void*       user_data)
{
    if (!user_data) return;

    // FIM baselines files only, so the netns flags carry no information here;
    // they are reported by the Syscollector consumer, which does collect
    // network-namespace-scoped rows.
    (void)netns_host_scoped;
    (void)netns_unreadable;

    static_cast<BaselineDriver*>(user_data)->onStatus(container_id, partial != 0);
}

void container_id_sink(const char* container_id, void* user_data)
{
    if (!container_id || !user_data) return;
    static_cast<std::set<std::string>*>(user_data)->insert(container_id);
}


/// Is `path` inside the configured monitored path `root`?
///
/// This is the prefix filter C22 makes necessary. An `ATTR` event on a
/// container's rootfs also arrives under a HOST path
/// (/var/lib/containerd/.../snapshots/117/fs/tmp/x), attributed to the
/// container's cgroup; resolving that under /proc/<pid>/root would look for a
/// file that does not exist inside the container. Requiring a staged path to sit
/// under something the operator actually configured discards those, because no
/// realistic configuration monitors the runtime's snapshot directory.
bool PathIsUnder(const std::string& path, const char* root)
{
    if (root == nullptr || root[0] == '\0') return false;

    const std::string prefix{root};

    if (prefix == "/") return path.size() > 1 && path[0] == '/';
    if (path.size() < prefix.size()) return false;
    if (path.compare(0, prefix.size(), prefix) != 0) return false;

    // Exactly the configured entry, or a child of it. The length check is what
    // stops "/etc" matching "/etcpasswd".
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

/// Turns the staged paths into one zero-recursion MonitoredPath each, keeping
/// the hash policy of whichever configured entry contains them.
///
/// `storage` owns the strings, because cb_monitored_path_t holds a borrowed
/// const char*.
std::vector<cb_monitored_path_t> SelectReconcilePaths(const std::vector<std::string>& staged,
                                                       const cb_monitored_path_t*      configured,
                                                       size_t                          configured_count,
                                                       std::vector<std::string>&       storage)
{
    std::vector<cb_monitored_path_t> selected;

    storage.reserve(staged.size());
    selected.reserve(staged.size());

    for (const auto& path : staged) {
        for (size_t i = 0; i < configured_count; ++i) {
            if (!PathIsUnder(path, configured[i].internal_path)) continue;

            storage.push_back(path);

            cb_monitored_path_t entry = configured[i];
            entry.internal_path   = storage.back().c_str();
            entry.recursion_level = 0;  // this one file, not a tree
            entry.max_files       = 1;
            selected.push_back(entry);
            break;
        }
    }

    return selected;
}

/// Acts on one batch from the eBPF drain. Runs on the consumer thread, so
/// nothing here may throw out of it.
void ReconcileBatch(const fim_container_events::ReconcileRequest& request)
{
    using fim_container_events::ReconcileMode;

    if (request.mode == ReconcileMode::rebaselineAll) {
        // Loss nobody could attribute. The whole-node walk already knows how to
        // do this safely, including the reachability gate on its stale sweep.
        LogDebug("Container FIM reconcile: unattributable event loss; re-baselining every container.");
        fim_run_container_baseline();
        return;
    }

    if (request.container_id.empty()) return;

    cb_monitored_path_t* paths      = nullptr;
    size_t               path_count = 0;

    if (fim_collect_container_monitored_paths(&paths, &path_count) != 0) return;
    if (!paths || path_count == 0U) return;

    try {
        if (request.mode == ReconcileMode::rewalkContainer) {
            // A walk sees whole directories, so it can tell a deleted file from
            // an unreadable one: delete detection is allowed, still gated on the
            // scan being reported complete.
            BaselineDriver driver{/*may_detect_deletions=*/true, CB_FIM_ORIGIN_EVENT};

            const int outcome = cbaseline_run_fim_dbsync_container(CB_DEFAULT_CONNECTOR_SOCKET_PATH,
                                                                    request.container_id.c_str(),
                                                                    paths,
                                                                    static_cast<int>(path_count),
                                                                    dbsync_sink,
                                                                    status_sink,
                                                                    fim_container_baseline_rate_limit,
                                                                    &driver);

            if (outcome < 0) {
                LogDebug("Container FIM reconcile: connector unavailable while re-walking container "
                         "'%s'; its rows are kept and the next event or scheduled baseline retries.",
                         request.container_id.c_str());
            } else {
                LogDebug("Container FIM reconcile: re-walked container '%s' (%d), %zu row(s).",
                         request.container_id.c_str(), outcome, driver.rows());
            }
        } else {
            std::vector<std::string>       storage;
            const auto selected = SelectReconcilePaths(request.paths, paths, path_count, storage);

            if (selected.empty()) {
                // Everything staged for this container fell outside the
                // configured paths — C22 host-form paths, or activity in a
                // directory nobody asked to monitor. Nothing to do, and
                // certainly nothing to delete.
                LogDebug("Container FIM reconcile: none of the %zu changed path(s) for container '%s' "
                         "are under a configured container directory; nothing to reconcile.",
                         request.paths.size(), request.container_id.c_str());
            } else {
                // D15: NEVER delete from a path reconcile. Its rows are a subset
                // of the container's files by design, and delete detection over a
                // subset would delete everything not named in this batch.
                BaselineDriver driver{/*may_detect_deletions=*/false, CB_FIM_ORIGIN_EVENT};

                cbaseline_run_fim_dbsync_container(CB_DEFAULT_CONNECTOR_SOCKET_PATH,
                                                   request.container_id.c_str(),
                                                   selected.data(),
                                                   static_cast<int>(selected.size()),
                                                   dbsync_sink,
                                                   status_sink,
                                                   fim_container_baseline_rate_limit,
                                                   &driver);

                LogDebug("Container FIM reconcile: re-read %zu path(s) for container '%s', %zu row(s).",
                         selected.size(), request.container_id.c_str(), driver.rows());
            }
        }
    } catch (const std::exception& err) {
        LogError("Container FIM reconcile failed: %s", err.what());
    } catch (...) {
        LogError("Container FIM reconcile failed with an unknown error.");
    }

    fim_free_container_monitored_paths(paths);
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

    // Nothing below may throw into main(): this runs on syscheckd's main
    // thread, which has no handler of its own.
    try {
        BaselineDriver driver;

        // check_max_fps() is FIM's own files-per-second token bucket, driven by
        // syscheck.max_files_per_second. It is process-global, so the container
        // walk shares one budget with the host walk rather than adding an
        // unbounded second source of file I/O (NFR3).
        const int baselined = cbaseline_run_fim_dbsync(CB_DEFAULT_CONNECTOR_SOCKET_PATH,
                                                       paths,
                                                       static_cast<int>(path_count),
                                                       dbsync_sink,
                                                       status_sink,
                                                       fim_container_baseline_rate_limit,
                                                       &driver);

        // Every container container_instances still knows about, INCLUDING ones
        // that are merely stopped and therefore produced no rows above. Without
        // this distinction a container restart would delete all of its FIM
        // state and re-create it — a false-positive flood on exactly the event
        // that must be reported accurately.
        std::set<std::string> known;
        const int listed = cbaseline_list_containers(CB_DEFAULT_CONNECTOR_SOCKET_PATH, container_id_sink, &known);

        // A negative count means the connector never answered, so `known` is
        // empty for want of an answer rather than for want of containers.
        // Sweeping against it would delete every container's FIM state. Skip
        // the sweep and keep the rows: a stale row costs one cycle of accuracy,
        // whereas deleting a live container's whole baseline costs a
        // false-delete flood plus a full re-seed.
        if (listed < 0) {
            LogError("Container FIM baseline: container connector unavailable, "
                     "skipping stale-container cleanup to avoid false deletions.");
        } else {
            driver.sweepStale(known);
        }

        if (driver.malformedRows() > 0) {
            LogDebug("Container FIM baseline: discarded %zu malformed row(s).", driver.malformedRows());
        }

        fim_report_container_baseline_result(baselined,
                                             driver.rows(),
                                             driver.partial(),
                                             driver.stale(),
                                             known.size());
    } catch (const std::exception& err) {
        LogError("Container FIM baseline failed: %s", err.what());
    } catch (...) {
        LogError("Container FIM baseline failed with an unknown error.");
    }

    fim_free_container_monitored_paths(paths);
}

extern "C" void fim_container_events_start(void)
{
    // Subscribe-first: this runs BEFORE the baseline walk, so a file changed
    // while the walk is in progress is staged and reconciled afterwards instead
    // of falling into the gap between "the walk read this file" and "monitoring
    // started".
    fim_container_events::DrainConfig config;
    config.connector_socket_path = CB_DEFAULT_CONNECTOR_SOCKET_PATH;

    // A daemonised agent's CWD is not its install directory, so the engine's
    // CWD-relative fallback would not find the object.
    char resolved[PATH_MAX] = {0};
    if (fim_container_baseline_abspath(CB_RT_BPF_OBJECT_PATH, resolved, sizeof(resolved)) == 0) {
        config.bpf_object_path = resolved;
    }

    try {
        if (!fim_container_events::ContainerEventDrain::instance().start(config, ReconcileBatch)) {
            return;
        }
    } catch (const std::exception& err) {
        LogError("Container eBPF drain failed to start: %s", err.what());
    } catch (...) {
        LogError("Container eBPF drain failed to start with an unknown error.");
    }
}

extern "C" void fim_container_events_release(void)
{
    // This IS the first-scan boundary: main() calls it once the whole-node
    // baseline has returned, and it is what lets the reconcile consumer touch
    // file_entry at all. Everything reconciled from here on is a real change to
    // a file that was already accounted for, so it alerts; the baseline's own
    // rows — every file in every container — do not. Same rule host FIM applies
    // through notify_scan / <notify_first_scan>.
    //
    // Before the delegation below, not after: release() returns early when the
    // drain never started (no eBPF engine), and the boundary has still been
    // crossed in that case.
    fim_container_baseline_first_scan_done();

    fim_container_events::ContainerEventDrain::instance().release();
}

extern "C" void fim_container_events_stop(void)
{
    fim_container_events::ContainerEventDrain::instance().stop();
}

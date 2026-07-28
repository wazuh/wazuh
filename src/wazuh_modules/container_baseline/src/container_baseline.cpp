#include "container_baseline.h"

#include "container_baseline_scanner.hpp"
#include "reconcile/collect_container.hpp"
#include "reconcile/container_inventory_reconciler.hpp"
#include "reconcile/container_lister.hpp"
#include "reconcile/sqlite_prior_state_store.hpp"

#include <memory>
#include <vector>

using wazuh::container_baseline::CollectContainer;
using wazuh::container_baseline::ContainerInventoryReconciler;
using wazuh::container_baseline::ContainerLister;
using wazuh::container_baseline::EmittedRow;
using wazuh::container_baseline::MonitoredPath;
using wazuh::container_baseline::ReconcileScope;
using wazuh::container_baseline::RunFimBaseline;
using wazuh::container_baseline::RunSyscollectorBaseline;
using wazuh::container_baseline::SqlitePriorStateStore;

namespace {

wazuh::container_baseline::RowSink MakeSink(cb_row_sink_t sink, void* user_data)
{
    return [sink, user_data](const EmittedRow& row) {
        if (sink == nullptr) return;
        sink(row.id.c_str(), row.operation, row.index.c_str(), row.json.c_str(), row.version, user_data);
    };
}

} // namespace

// Owns the reconciler's collaborators for the lifetime of the C handle. Member
// order matters: the reconciler holds references to the lister and store, so it
// is declared last (destroyed first).
struct cbaseline_reconciler
{
    SqlitePriorStateStore        store;
    ContainerLister              lister;
    ContainerInventoryReconciler reconciler;

    cbaseline_reconciler(const char* socket, const char* db, cb_row_sink_t sink, void* user_data)
        : store(db)
        , lister(socket)
        , reconciler(lister, store, CollectContainer, MakeSink(sink, user_data))
    {
    }
};

extern "C" int cbaseline_run_fim(const char*                connector_socket_path,
                                  const cb_monitored_path_t* paths,
                                  int                        path_count,
                                  cb_row_sink_t              sink,
                                  void*                      user_data)
{
    if (connector_socket_path == nullptr || path_count < 0) return 0;

    std::vector<MonitoredPath> cxx_paths;
    cxx_paths.reserve(static_cast<size_t>(path_count));
    for (int i = 0; i < path_count; ++i) {
        const auto& p = paths[i];
        MonitoredPath mp;
        mp.internal_path   = (p.internal_path != nullptr) ? p.internal_path : "";
        mp.recursion_level = p.recursion_level;
        if (p.max_files != 0)      mp.max_files      = p.max_files;
        if (p.max_hash_bytes != 0) mp.max_hash_bytes = p.max_hash_bytes;
        if (!mp.internal_path.empty()) cxx_paths.push_back(std::move(mp));
    }

    return RunFimBaseline(connector_socket_path, cxx_paths, MakeSink(sink, user_data));
}

extern "C" int cbaseline_run_syscollector(const char* connector_socket_path, cb_row_sink_t sink, void* user_data)
{
    if (connector_socket_path == nullptr) return 0;
    return RunSyscollectorBaseline(connector_socket_path, MakeSink(sink, user_data));
}

extern "C" cbaseline_reconciler_t* cbaseline_reconciler_create(const char*   connector_socket_path,
                                                               const char*   prior_state_db_path,
                                                               cb_row_sink_t sink,
                                                               void*         user_data)
{
    if (connector_socket_path == nullptr || prior_state_db_path == nullptr) return nullptr;
    try
    {
        return new cbaseline_reconciler(connector_socket_path, prior_state_db_path, sink, user_data);
    }
    catch (...)
    {
        // Prior-state DB unopenable (permissions, disk) — fail closed; the caller
        // logs and skips container inventory rather than crashing the module.
        return nullptr;
    }
}

extern "C" int cbaseline_reconciler_run(cbaseline_reconciler_t* handle)
{
    if (handle == nullptr) return -1;
    try
    {
        const auto stats = handle->reconciler.reconcile(ReconcileScope{});
        return stats.skipped_unavailable ? -1 : stats.containers_scanned;
    }
    catch (...)
    {
        return -1;
    }
}

extern "C" void cbaseline_reconciler_destroy(cbaseline_reconciler_t* handle)
{
    delete handle;
}

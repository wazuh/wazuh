#include "container_baseline.h"

#include "container_baseline_scanner.hpp"
#include "reconcile/collect_container.hpp"
#include "reconcile/container_inventory_reconciler.hpp"
#include "reconcile/container_lister.hpp"
#include "reconcile/sqlite_prior_state_store.hpp"

#include <memory>
#include <utility>
#include <vector>

using wazuh::container_baseline::CollectContainer;
using wazuh::container_baseline::ContainerInventoryReconciler;
using wazuh::container_baseline::ContainerLister;
using wazuh::container_baseline::EmittedRow;
using wazuh::container_baseline::ListContainers;
using wazuh::container_baseline::MonitoredPath;
using wazuh::container_baseline::ReconcileScope;
using wazuh::container_baseline::RunFimBaseline;
using wazuh::container_baseline::RunFimDbsyncBaseline;
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

// Index strings mirror the literals CollectContainer() (container_baseline_scanner.cpp)
// hardcodes for each dimension. Only nonzero fields are inserted — limitFor()
// already treats an absent key as unlimited, same as an explicit 0.
wazuh::container_baseline::DocumentLimits MakeDocumentLimits(const cb_document_limits_t* limits)
{
    wazuh::container_baseline::DocumentLimits out;
    if (limits == nullptr) return out;

    const std::pair<std::size_t, const char*> fields[] = {
        {limits->processes,        "wazuh-states-inventory-processes"},
        {limits->ports,            "wazuh-states-inventory-ports"},
        {limits->packages,         "wazuh-states-inventory-packages"},
        {limits->users,            "wazuh-states-inventory-users"},
        {limits->groups,           "wazuh-states-inventory-groups"},
        {limits->os_info,          "wazuh-states-inventory-system"},
        {limits->network_iface,    "wazuh-states-inventory-interfaces"},
        {limits->network_protocol, "wazuh-states-inventory-protocols"},
        {limits->network_address,  "wazuh-states-inventory-networks"},
        {limits->hardware,         "wazuh-states-inventory-hardware"},
    };
    for (const auto& [value, index] : fields) {
        if (value != 0) out[index] = value;
    }
    return out;
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

    cbaseline_reconciler(const char* socket, const char* db, cb_row_sink_t sink, void* user_data,
                         const cb_document_limits_t* limits)
        : store(db)
        , lister(socket)
        , reconciler(lister, store, CollectContainer, MakeSink(sink, user_data), MakeDocumentLimits(limits))
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

extern "C" int cbaseline_run_syscollector_dbsync(const char*          connector_socket_path,
                                                 cb_dbsync_row_sink_t sink,
                                                 void*                user_data)
{
    if (connector_socket_path == nullptr) return 0;
    return wazuh::container_baseline::RunSyscollectorDbsyncBaseline(
        connector_socket_path,
        [sink, user_data](const wazuh::container_baseline::DbsyncRow& row) {
            if (sink == nullptr) return;
            sink(row.container_id.c_str(), row.table.c_str(), row.json.c_str(), user_data);
        });
}

extern "C" int cbaseline_list_containers(const char* connector_socket_path, cb_container_id_sink_t sink, void* user_data)
{
    if (connector_socket_path == nullptr) return 0;
    return ListContainers(
        connector_socket_path,
        [sink, user_data](const std::string& containerId) {
            if (sink == nullptr) return;
            sink(containerId.c_str(), user_data);
        });
}

extern "C" int cbaseline_run_fim_dbsync(const char*                connector_socket_path,
                                         const cb_monitored_path_t* paths,
                                         int                        path_count,
                                         cb_dbsync_row_sink_t       sink,
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

    return RunFimDbsyncBaseline(
        connector_socket_path,
        cxx_paths,
        [sink, user_data](const wazuh::container_baseline::DbsyncRow& row) {
            if (sink == nullptr) return;
            sink(row.container_id.c_str(), row.table.c_str(), row.json.c_str(), user_data);
        });
}

extern "C" cbaseline_reconciler_t* cbaseline_reconciler_create(const char*                connector_socket_path,
                                                               const char*                prior_state_db_path,
                                                               cb_row_sink_t              sink,
                                                               void*                      user_data,
                                                               const cb_document_limits_t* limits)
{
    if (connector_socket_path == nullptr || prior_state_db_path == nullptr) return nullptr;
    try
    {
        return new cbaseline_reconciler(connector_socket_path, prior_state_db_path, sink, user_data, limits);
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

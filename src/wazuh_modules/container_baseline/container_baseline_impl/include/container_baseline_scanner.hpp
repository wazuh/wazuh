#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One row emitted to the sync-protocol layer. `operation` matches the
/// sync_protocol Operation_t values (0 = CREATE) but is passed as a plain int
/// so this header has no dependency on agent_sync_protocol_c_interface_types.h —
/// callers translate to their own Operation_t/Operation enum at the call site.
struct EmittedRow
{
    std::string id;
    int         operation{0}; // OPERATION_CREATE
    std::string index;
    std::string json;
    uint64_t    version{1};
};

using RowSink = std::function<void(const EmittedRow&)>;

/// @brief A single `<directories type="kubernetes">`-style entry: an in-container
/// path to walk, independent of any one syscheck.h type so this module has no
/// compile-time dependency on syscheckd's config headers. The FIM call site
/// (src/syscheckd/src/container_baseline_fim.c) is responsible for translating
/// syscheck.k8s_directories (k8s_monitored_path_t) into a vector of these.
struct MonitoredPath
{
    std::string internal_path;
    int         recursion_level{-1};
    size_t      max_files{20000};      // NFR3-style hard cap; see rootfs_file_walker.hpp.
    size_t      max_hash_bytes{104857600}; // 100 MiB per file, mirrors FIM's own diff-size-limit spirit.
};

/// @brief Run the FIM file baseline for every container currently known to the
/// container_instances, over every configured MonitoredPath, and hand each
/// resulting row to `sink`.
///
/// @param connector_socket_path Unix socket path of the container_instances IPC
///                                server (see container_instances_client.hpp).
/// @param paths Monitored in-container paths (translated from syscheck.k8s_directories).
/// @param sink Callback invoked once per file row; the caller (syscheckd) is
///             responsible for actually persisting it via its own sync_handle.
/// @return Number of containers that were baselined (i.e. had at least one live
///         PID resolvable); containers with cgroup_id but no live PID are
///         skipped and logged by the caller via the returned count mismatch.
int RunFimBaseline(const std::string&          connector_socket_path,
                    const std::vector<MonitoredPath>& paths,
                    const RowSink&               sink);

/// @brief Run the Syscollector process+network baseline for every container
/// currently known to container_instances, and hand each resulting row to
/// `sink`. See baseline_rows.hpp for the draft-schema caveat on the JSON shape.
int RunSyscollectorBaseline(const std::string& connector_socket_path, const RowSink& sink);

/// @brief One baseline row rendered in syscollector's dbsync_* column format
/// (Option A: baseline through the host event flow). `json` is a flat object of
/// dbsync columns (including container_id/container_json); `table` is the
/// dbsync table name ("dbsync_processes", ...). The consumer (syscollector)
/// groups rows per container per table and pushes them through per-container
/// scoped DBSync transactions so the existing notifyChange/processEvent
/// pipeline emits the deltas.
struct DbsyncRow
{
    std::string container_id;
    std::string table;
    std::string json;
};

using DbsyncRowSink = std::function<void(const DbsyncRow&)>;

/// @brief Same scan coverage as RunFimBaseline() but emitting raw file_entry
/// dbsync rows (BuildFimFileDbsyncRow + checksum) instead of pre-shaped
/// sync-protocol payloads. The consumer (syscheckd container_baseline_fim.cpp)
/// groups rows per container and pushes them through per-container scoped
/// fim_db_transaction_start transactions so the existing transaction_callback
/// pipeline emits the deltas.
/// @return Number of containers baselined (same semantics as RunFimBaseline).
int RunFimDbsyncBaseline(const std::string&                connector_socket_path,
                          const std::vector<MonitoredPath>& paths,
                          const DbsyncRowSink&              sink);

/// @brief Same scan coverage as RunSyscollectorBaseline() but emitting raw
/// dbsync rows (Build*DbsyncRow) instead of pre-shaped sync-protocol payloads.
/// @return Number of containers baselined (same semantics as RunFimBaseline).
int RunSyscollectorDbsyncBaseline(const std::string& connector_socket_path, const DbsyncRowSink& sink);

using ContainerIdSink = std::function<void(const std::string&)>;

/// @brief Lists every container currently known to container_instances,
/// independent of whether it has a resolvable live PID right now — unlike the
/// Run*Baseline() functions above, a momentarily-stopped container (known,
/// but no live PID) is still reported here. Callers that need to tell
/// "stopped" apart from "gone" should compare this list against a
/// Run*Baseline() call's output rather than treating "produced no rows" as
/// "removed".
/// @return Number of containers reported through `sink`.
int ListContainers(const std::string& connector_socket_path, const ContainerIdSink& sink);

} // namespace wazuh::container_baseline

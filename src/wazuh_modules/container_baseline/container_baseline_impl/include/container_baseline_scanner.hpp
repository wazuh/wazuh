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
/// container-connector, over every configured MonitoredPath, and hand each
/// resulting row to `sink`.
///
/// @param connector_socket_path Unix socket path of the container-connector IPC
///                                server (see container_connector_client.hpp).
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
/// currently known to the container-connector, and hand each resulting row to
/// `sink`. See baseline_rows.hpp for the draft-schema caveat on the JSON shape.
int RunSyscollectorBaseline(const std::string& connector_socket_path, const RowSink& sink);

} // namespace wazuh::container_baseline

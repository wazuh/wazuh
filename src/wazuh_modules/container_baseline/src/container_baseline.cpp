#include "container_baseline.h"

#include "container_baseline_scanner.hpp"

#include <functional>
#include <string>
#include <vector>

using wazuh::container_baseline::ContainerStatus;
using wazuh::container_baseline::ContainerStatusSink;
using wazuh::container_baseline::DbsyncRow;
using wazuh::container_baseline::ListContainers;
using wazuh::container_baseline::MonitoredPath;
using wazuh::container_baseline::RunFimDbsyncBaseline;
using wazuh::container_baseline::RunFimDbsyncBaselineForContainer;
using wazuh::container_baseline::RunSyscollectorDbsyncBaseline;

namespace {

/// `keep_unusable` controls what happens to an entry with no internal_path.
///
/// The whole-node entry points pass false and drop it: their paths come from
/// agent configuration, where an empty entry is a config mistake affecting every
/// container equally, and there is no per-call channel to report it on.
///
/// The single-container entry point passes true, so the empty path survives
/// translation and is rejected downstream by IsSafeInternalPath(), which forces
/// the scan to be reported PARTIAL. Dropping it silently there would let a caller
/// ask for three paths, receive rows for two, be told the scan was complete, and
/// delete the stored rows for the third.
std::vector<MonitoredPath> TranslatePaths(const cb_monitored_path_t* paths, int path_count,
                                          bool keep_unusable = false)
{
    std::vector<MonitoredPath> out;
    if (paths == nullptr || path_count <= 0) return out;

    out.reserve(static_cast<size_t>(path_count));
    for (int i = 0; i < path_count; ++i) {
        const auto& p = paths[i];
        const bool  unusable = (p.internal_path == nullptr || p.internal_path[0] == '\0');
        if (unusable && !keep_unusable) continue;

        MonitoredPath mp;
        mp.internal_path   = unusable ? std::string{} : std::string{p.internal_path};
        mp.recursion_level = p.recursion_level;
        if (p.max_files != 0)      mp.max_files      = p.max_files;
        if (p.max_hash_bytes != 0) mp.max_hash_bytes = p.max_hash_bytes;

        // All-zero means the caller didn't express a preference; compute all
        // three rather than silently emitting rows with no hashes at all.
        if (p.hash_md5 != 0 || p.hash_sha1 != 0 || p.hash_sha256 != 0) {
            mp.hashes.md5    = (p.hash_md5 != 0);
            mp.hashes.sha1   = (p.hash_sha1 != 0);
            mp.hashes.sha256 = (p.hash_sha256 != 0);
        }

        out.push_back(std::move(mp));
    }
    return out;
}

wazuh::container_baseline::DbsyncRowSink MakeRowSink(cb_dbsync_row_sink_t sink, void* user_data)
{
    return [sink, user_data](const DbsyncRow& row) {
        if (sink == nullptr) return;
        sink(row.container_id.c_str(), row.table.c_str(), row.json.c_str(), user_data);
    };
}

ContainerStatusSink MakeStatusSink(cb_container_status_sink_t sink, void* user_data)
{
    if (sink == nullptr) return {};

    return [sink, user_data](const ContainerStatus& status) {
        sink(status.container_id.c_str(),
             status.partial ? 1 : 0,
             status.netns_host_scoped ? 1 : 0,
             status.netns_unreadable ? 1 : 0,
             user_data);
    };
}

} // namespace

extern "C" int cbaseline_run_fim_dbsync(const char*                connector_socket_path,
                                         const cb_monitored_path_t* paths,
                                         int                        path_count,
                                         cb_dbsync_row_sink_t       sink,
                                         cb_container_status_sink_t status_sink,
                                         cb_rate_limit_fn           rate_limit,
                                         void*                      user_data)
{
    if (connector_socket_path == nullptr || path_count < 0) return 0;

    std::function<void()> throttle;
    if (rate_limit != nullptr) throttle = [rate_limit]() { rate_limit(); };

    return RunFimDbsyncBaseline(connector_socket_path,
                                TranslatePaths(paths, path_count),
                                MakeRowSink(sink, user_data),
                                MakeStatusSink(status_sink, user_data),
                                throttle);
}

extern "C" int cbaseline_run_fim_dbsync_container(const char*                connector_socket_path,
                                                  const char*                container_id,
                                                  const cb_monitored_path_t* paths,
                                                  int                        path_count,
                                                  cb_dbsync_row_sink_t       sink,
                                                  cb_container_status_sink_t status_sink,
                                                  cb_rate_limit_fn           rate_limit,
                                                  void*                      user_data)
{
    // -1, not 0: with no socket configured we have not established anything
    // about this container, and 0 would read as "it has no files". Same
    // reasoning as cbaseline_list_containers() below.
    if (connector_socket_path == nullptr) return -1;

    // 0, not -1: a missing id or a negative count is a caller bug, not a
    // statement about the connector. Either way nothing was baselined.
    if (container_id == nullptr || container_id[0] == '\0' || path_count < 0) return 0;

    std::function<void()> throttle;
    if (rate_limit != nullptr) throttle = [rate_limit]() { rate_limit(); };

    return RunFimDbsyncBaselineForContainer(connector_socket_path,
                                            container_id,
                                            TranslatePaths(paths, path_count, /*keep_unusable=*/true),
                                            MakeRowSink(sink, user_data),
                                            MakeStatusSink(status_sink, user_data),
                                            throttle);
}

extern "C" int cbaseline_run_syscollector_dbsync(const char*                connector_socket_path,
                                                  cb_dbsync_row_sink_t       sink,
                                                  cb_container_status_sink_t status_sink,
                                                  void*                      user_data)
{
    if (connector_socket_path == nullptr) return 0;

    return RunSyscollectorDbsyncBaseline(connector_socket_path,
                                         MakeRowSink(sink, user_data),
                                         MakeStatusSink(status_sink, user_data));
}

extern "C" int cbaseline_list_containers(const char* connector_socket_path, cb_container_id_sink_t sink, void* user_data)
{
    // -1, not 0: "no socket configured" is no more an authorisation to delete
    // rows than "socket unreachable" is. See the header's contract.
    if (connector_socket_path == nullptr) return -1;
    return ListContainers(
        connector_socket_path,
        [sink, user_data](const std::string& containerId) {
            if (sink == nullptr) return;
            sink(containerId.c_str(), user_data);
        });
}

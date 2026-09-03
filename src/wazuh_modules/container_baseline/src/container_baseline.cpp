#include "container_baseline.h"

#include "container_baseline_scanner.hpp"

#include <functional>
#include <vector>

using wazuh::container_baseline::ContainerStatus;
using wazuh::container_baseline::ContainerStatusSink;
using wazuh::container_baseline::DbsyncRow;
using wazuh::container_baseline::ListContainers;
using wazuh::container_baseline::MonitoredPath;
using wazuh::container_baseline::RunFimDbsyncBaseline;
using wazuh::container_baseline::RunSyscollectorDbsyncBaseline;

namespace {

std::vector<MonitoredPath> TranslatePaths(const cb_monitored_path_t* paths, int path_count)
{
    std::vector<MonitoredPath> out;
    if (paths == nullptr || path_count <= 0) return out;

    out.reserve(static_cast<size_t>(path_count));
    for (int i = 0; i < path_count; ++i) {
        const auto& p = paths[i];
        if (p.internal_path == nullptr || p.internal_path[0] == '\0') continue;

        MonitoredPath mp;
        mp.internal_path   = p.internal_path;
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

#include "container_baseline.h"

#include "container_baseline_scanner.hpp"

#include <vector>

using wazuh::container_baseline::EmittedRow;
using wazuh::container_baseline::MonitoredPath;
using wazuh::container_baseline::RunFimBaseline;
using wazuh::container_baseline::RunFimDbsyncBaseline;
using wazuh::container_baseline::RunSyscollectorBaseline;

namespace {

wazuh::container_baseline::RowSink MakeSink(cb_row_sink_t sink, void* user_data)
{
    return [sink, user_data](const EmittedRow& row) {
        if (sink == nullptr) return;
        sink(row.id.c_str(), row.operation, row.index.c_str(), row.json.c_str(), row.version, user_data);
    };
}

} // namespace

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

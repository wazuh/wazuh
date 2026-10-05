#include "container_baseline.h"

#include "container_baseline_scanner.hpp"
#include "container_instances_client.hpp"

#include <cstddef>
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
        cb_container_status_t out{};

        out.container_id      = status.container_id.c_str();
        out.partial           = status.partial ? 1 : 0;
        out.row_cap_hit       = status.row_cap_hit ? 1 : 0;
        out.rootfs_unreadable = status.rootfs_unreadable ? 1 : 0;
        out.paths_rejected    = status.paths_rejected ? 1 : 0;
        out.roots_missing     = status.roots_missing;
        out.roots_scanned     = status.roots_scanned;
        out.netns_host_scoped = status.netns_host_scoped ? 1 : 0;
        out.netns_unreadable  = status.netns_unreadable ? 1 : 0;

        /* `out` and the string it borrows both outlive the call: the sink
         * contract is synchronous, and a consumer that keeps the pointer past
         * it was already broken by container_id. */
        sink(&out, user_data);
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

extern "C" int cbaseline_run_syscollector_dbsync_for(const char*                connector_socket_path,
                                                     const char* const*         container_ids,
                                                     int                        container_count,
                                                     cb_dbsync_row_sink_t       sink,
                                                     cb_container_status_sink_t status_sink,
                                                     void*                      user_data)
{
    // -1, matching the whole-node entry points: "no socket configured" is no
    // more an authorisation to act than "socket unreachable" is.
    if (connector_socket_path == nullptr) return -1;

    // 0, not -1: an empty or malformed list is a caller bug, and says nothing
    // about the connector. Nothing was baselined either way.
    if (container_ids == nullptr || container_count <= 0) return 0;

    std::vector<std::string> ids;
    ids.reserve(static_cast<std::size_t>(container_count));

    for (int i = 0; i < container_count; ++i)
    {
        if (container_ids[i] != nullptr && container_ids[i][0] != '\0')
        {
            ids.emplace_back(container_ids[i]);
        }
    }

    if (ids.empty()) return 0;

    return RunSyscollectorDbsyncBaselineForContainers(
        connector_socket_path, ids, MakeRowSink(sink, user_data), MakeStatusSink(status_sink, user_data));
}

extern "C" int cbaseline_lifecycle_since(const char*         connector_socket_path,
                                         unsigned long long* epoch,
                                         unsigned long long* seq,
                                         cb_lifecycle_sink_t sink,
                                         void*               user_data)
{
    if (connector_socket_path == nullptr || epoch == nullptr || seq == nullptr)
    {
        return CB_DELTA_UNAVAILABLE;
    }

    wazuh::container_instances_client::ContainerInstancesClient client {connector_socket_path};
    const auto delta = client.listContainersSince(*epoch, *seq);

    if (!delta.available)
    {
        // Nothing was obtained. Deliberately NOT distinguished from any other
        // failure here, because every one of them has the same consequence for
        // the caller: it learned nothing, so it may not act as though it did.
        return CB_DELTA_UNAVAILABLE;
    }

    // An older module answered with the whole set and no cursor. Reporting that
    // as a resync is exactly right — the caller re-baselines what it is told
    // about, which is what it would have done anyway — and means this function
    // has no separate "talking to an old module" path for callers to handle.
    if (!delta.deltaSupported || delta.resyncRequired)
    {
        if (sink != nullptr)
        {
            for (const auto& container : delta.containers)
            {
                cb_lifecycle_event_t event {};
                event.container_id = container.containerId.c_str();
                event.kind = CB_LIFECYCLE_ADDED;
                event.changed = 0;
                sink(&event, user_data);
            }
        }

        *epoch = delta.epoch;
        *seq = delta.seq;
        return CB_DELTA_RESYNC;
    }

    int reported = 0;

    for (const auto& item : delta.events)
    {
        if (sink == nullptr) break;

        cb_lifecycle_event_t event {};
        event.container_id = item.containerId.c_str();
        event.changed = 0;

        switch (item.kind)
        {
            using Kind = wazuh::container_instances_client::ContainerEventRef::Kind;
            case Kind::added: event.kind = CB_LIFECYCLE_ADDED; break;
            case Kind::removed: event.kind = CB_LIFECYCLE_REMOVED; break;
            case Kind::changed:
            default: event.kind = CB_LIFECYCLE_CHANGED; break;
        }

        for (const auto& name : item.changed)
        {
            if (name == "identity") event.changed |= CB_CHANGED_IDENTITY;
            else if (name == "image") event.changed |= CB_CHANGED_IMAGE;
            else if (name == "mounts") event.changed |= CB_CHANGED_MOUNTS;
            else if (name == "network") event.changed |= CB_CHANGED_NETWORK;
            else if (name == "metadata") event.changed |= CB_CHANGED_METADATA;
            else
            {
                // A class this build has no bit for. Setting every known bit is
                // the conservative reading: the caller re-scans everything,
                // which is what an unknown change deserves. Dropping it would
                // silently skip work that was owed.
                event.changed |= CB_CHANGED_IDENTITY | CB_CHANGED_IMAGE | CB_CHANGED_MOUNTS | CB_CHANGED_NETWORK |
                                 CB_CHANGED_METADATA;
            }
        }

        sink(&event, user_data);
        ++reported;
    }

    // Advanced only after every event has been handed over, so a caller that
    // dies mid-loop replays them rather than losing them.
    *epoch = delta.epoch;
    *seq = delta.seq;

    return reported;
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

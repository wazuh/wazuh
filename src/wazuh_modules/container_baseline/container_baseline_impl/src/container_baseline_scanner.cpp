#include "container_baseline_scanner.hpp"

#include "baseline_rows.hpp"
#include "container_instances_client.hpp"
#include "hardware_scanner.hpp"
#include "interface_scanner.hpp"
#include "network_scanner.hpp"
#include "os_scanner.hpp"
#include "package_scanner.hpp"
#include "pid_resolver.hpp"
#include "process_scanner.hpp"
#include "protocol_scanner.hpp"
#include "reconcile/collect_container.hpp"
#include "reconcile/resolve_identity.hpp"
#include "rootfs_file_walker.hpp"
#include "service_scanner.hpp"
#include "user_scanner.hpp"

#include <json.hpp>

#include <atomic>
#include <chrono>
#include <set>
#include <thread>
#include <utility>

namespace wazuh::container_baseline {

namespace {

// The container_instances IPC socket binds before its connectors finish their
// first snapshot (list is a pure store read with no cold-cache refresh), so a
// baseline can see an "ok" but empty list while the store is still warming.
// Retry an empty list briefly — but only until the first time a non-empty
// list is actually seen: past that point, an empty result almost certainly
// means "no containers running" rather than "still warming up", and paying
// the full retry cost (up to kListRetryAttempts * kListRetryDelay) on every
// call once this baseline runs on a recurring schedule would otherwise add
// unbounded blocking latency to every such call.
constexpr int kListRetryAttempts = 10;
constexpr auto kListRetryDelay = std::chrono::milliseconds{500};
std::atomic<bool> g_everSawContainers{false};

// A non-empty list can still be *incomplete*: one connector (e.g. Docker) can
// be slower to finish its own initial enumeration than another (e.g.
// Kubernetes) that's already returning results -- confirmed directly on a
// real deployment (see #37533's startup-race-solutions-and-edge-cases.md):
// restarting only the FIM daemon while container_instances stayed warm took
// its baseline from 3 containers to the correct 4, with nothing else
// changed. Poll a few more times past the first non-empty result and accept
// once two consecutive polls agree on the exact set of container ids
// (content, not just count, so one container stopping while another starts
// between polls isn't mistaken for stability). Bounded and, like
// g_everSawContainers above, only paid until stability is actually observed
// once -- a node that's already settled never pays this again.
constexpr int kQuiescenceRetryAttempts = 5;
std::atomic<bool> g_containersStable{false};

std::set<std::string> ContainerIdSet(const std::vector<wazuh::container_instances_client::ContainerRef>& refs)
{
    std::set<std::string> ids;
    for (const auto& ref : refs)
    {
        ids.insert(ref.containerId);
    }
    return ids;
}

// Every container currently tracked by the container_instances store, paired
// with its resolved identity. One IPC round trip to list, then one lookup per
// listed container. The list call gives us cgroup ids, so the lookup can resolve
// the richer metadata in the same module that owns it.
std::vector<ContainerIdentity> DiscoverContainers(const std::string& socket_path)
{
    wazuh::container_instances_client::ContainerInstancesClient client(socket_path);
    std::vector<ContainerIdentity> out;

    std::vector<wazuh::container_instances_client::ContainerRef> refs;
    const int attempts = g_everSawContainers.load() ? 1 : kListRetryAttempts;
    for (int attempt = 1; attempt <= attempts; ++attempt)
    {
        refs = client.listContainers();
        if (!refs.empty() || attempt == attempts)
        {
            break;
        }
        std::this_thread::sleep_for(kListRetryDelay);
    }

    if (!refs.empty())
    {
        g_everSawContainers.store(true);
    }

    if (!refs.empty() && !g_containersStable.load())
    {
        auto last_ids = ContainerIdSet(refs);
        bool stable = false;
        for (int attempt = 1; attempt <= kQuiescenceRetryAttempts; ++attempt)
        {
            std::this_thread::sleep_for(kListRetryDelay);
            auto next_refs = client.listContainers();
            auto next_ids = ContainerIdSet(next_refs);
            if (next_ids == last_ids)
            {
                stable = true;
                break;
            }
            refs = std::move(next_refs);
            last_ids = std::move(next_ids);
        }

        if (stable)
        {
            g_containersStable.store(true);
        }
        // else: attempts exhausted without two consecutive polls agreeing --
        // proceed with whatever `refs` currently holds rather than blocking
        // this baseline run indefinitely. g_containersStable stays false, so
        // the *next* call (the recurring syscollector scan, or another
        // Run*Baseline invocation) tries the quiescence check again rather
        // than silently accepting a possibly-still-incomplete list forever.
    }

    for (const auto& ref : refs)
    {
        const auto lookup = client.resolveByCgroupId(ref.cgroupId, ref.containerId);
        if (lookup.status != wazuh::container_instances_client::LookupStatus::resolved)
        {
            out.push_back(ContainerIdentity{ref.containerId, nullptr});
            continue;
        }
        out.push_back(IdentityFromResolveJson(ref.containerId, lookup.json));
    }
    return out;
}

// Scan one dimension: stamp the shared container identity onto each row and wrap
// it as an EmittedRow addressed at `index`. The operation is nominal here
// (CREATE) — the reconciler's diff reassigns CREATE/MODIFY per row.
template <class Row, class Build>
CollectorResult CollectDim(const std::string& index, std::vector<Row> rows, const ContainerIdentity& identity,
                           Build build)
{
    CollectorResult result;
    result.index  = index;
    result.status = CollectStatus::Ok;
    result.rows.reserve(rows.size());
    for (auto& row : rows)
    {
        ApplyIdentity(row, identity);
        auto [id, json] = build(row);
        result.rows.push_back(EmittedRow{std::move(id), kOperationCreate, index, std::move(json), 1});
    }
    return result;
}

} // namespace

std::optional<std::vector<CollectorResult>> CollectContainer(const ContainerIdentity& identity)
{
    const auto pids = ResolvePidsForContainer(identity.container_id);
    if (pids.empty())
    {
        // Not addressable: no live PID to reach the rootfs/namespaces. Return
        // nullopt so the reconciler skips this container rather than diffing it to
        // empty and deleting a live container's rows.
        return std::nullopt;
    }
    const auto pid = pids.front();

    std::vector<CollectorResult> dims;
    dims.reserve(11);

    // cgroup-scoped dimensions (read by container id).
    dims.push_back(CollectDim("wazuh-states-inventory-processes", ScanContainerProcesses(identity.container_id),
                              identity, BuildProcessJson));
    dims.push_back(CollectDim("wazuh-states-inventory-ports", ScanContainerNetwork(identity.container_id), identity,
                              BuildPortJson));

    // rootfs / namespace-scoped dimensions (read via /proc/<pid>/root and setns).
    dims.push_back(CollectDim("wazuh-states-inventory-users", ScanContainerUsers(pid), identity, BuildUserJson));
    dims.push_back(CollectDim("wazuh-states-inventory-groups", ScanContainerGroups(pid), identity, BuildGroupJson));
    dims.push_back(
        CollectDim("wazuh-states-inventory-packages", ScanContainerPackages(pid), identity, BuildPackageJson));
    dims.push_back(CollectDim("wazuh-states-inventory-system", ScanContainerOs(pid), identity, BuildOsJson));

    auto ifscan = ScanContainerInterfaces(pid);
    dims.push_back(CollectDim("wazuh-states-inventory-interfaces", std::move(ifscan.interfaces), identity,
                              BuildInterfaceJson));
    dims.push_back(CollectDim("wazuh-states-inventory-networks", std::move(ifscan.addresses), identity,
                              BuildNetworkAddressJson));

    dims.push_back(
        CollectDim("wazuh-states-inventory-protocols", ScanContainerProtocols(pid), identity, BuildProtocolJson));
    dims.push_back(
        CollectDim("wazuh-states-inventory-services", ScanContainerServices(pid), identity, BuildServiceJson));
    dims.push_back(
        CollectDim("wazuh-states-inventory-hardware", ScanContainerHardware(pid), identity, BuildHardwareJson));

    return dims;
}

int RunFimBaseline(const std::string&                connector_socket_path,
                    const std::vector<MonitoredPath>& paths,
                    const RowSink&                     sink)
{
    int baselined = 0;

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        const auto pids = ResolvePidsForContainer(identity.container_id);
        if (pids.empty()) continue; // no live PID — nothing to address the rootfs with (yet).

        ++baselined;
        const auto pid = pids.front();

        for (const auto& path : paths) {
            const auto walk = WalkContainerPath(pid, path.internal_path, path.recursion_level,
                                                 path.max_files, path.max_hash_bytes);
            for (auto row : walk.rows) {
                ApplyIdentity(row, identity);
                auto [id, json] = BuildFimFileJson(row);
                sink(EmittedRow{id, kOperationCreate, "wazuh-states-fim-files", json, 1});
            }
        }
    }

    return baselined;
}

int RunSyscollectorBaseline(const std::string& connector_socket_path, const RowSink& sink)
{
    int baselined = 0;

    for (const auto& identity : DiscoverContainers(connector_socket_path))
    {
        const auto dims = CollectContainer(identity);
        if (!dims)
        {
            continue;  // not addressable (no live PID) — nothing to baseline.
        }

        ++baselined;
        for (const auto& dim : *dims)
        {
            for (const auto& row : dim.rows)
            {
                sink(row);  // rows already carry OPERATION_CREATE (one-shot baseline).
            }
        }
    }

    return baselined;
}

int RunFimDbsyncBaseline(const std::string&                connector_socket_path,
                          const std::vector<MonitoredPath>& paths,
                          const DbsyncRowSink&              sink)
{
    int baselined = 0;

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        const auto pids = ResolvePidsForContainer(identity.container_id);
        if (pids.empty()) continue;

        ++baselined;
        const auto pid = pids.front();
        const auto containerJson = BuildContainerContextJson(identity.container_id, identity.context);

        for (const auto& mp : paths) {
            const auto walk = WalkContainerPath(pid, mp.internal_path, mp.recursion_level,
                                                 mp.max_files, mp.max_hash_bytes);
            for (auto row : walk.rows) {
                ApplyIdentity(row, identity);
                sink(DbsyncRow{identity.container_id, "file_entry",
                               BuildFimFileDbsyncRow(row, containerJson)});
            }
        }
    }

    return baselined;
}

int RunSyscollectorDbsyncBaseline(const std::string& connector_socket_path, const DbsyncRowSink& sink)
{
    int baselined = 0;

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        const auto pids = ResolvePidsForContainer(identity.container_id);
        if (pids.empty()) continue;

        ++baselined;

        // Context blob serialized once per container; every row carries it in
        // its container_json column so DELETED events stay self-contained.
        const auto containerJson = BuildContainerContextJson(identity.container_id, identity.context);
        const auto emit = [&](const std::string& table, std::string json) {
            sink(DbsyncRow{identity.container_id, table, std::move(json)});
        };

        for (auto row : ScanContainerProcesses(identity.container_id)) {
            ApplyIdentity(row, identity);
            emit("dbsync_processes", BuildProcessDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerNetwork(identity.container_id)) {
            ApplyIdentity(row, identity);
            emit("dbsync_ports", BuildPortDbsyncRow(row, containerJson));
        }

        const auto pid = pids.front();

        for (auto row : ScanContainerUsers(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_users", BuildUserDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerGroups(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_groups", BuildGroupDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerPackages(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_packages", BuildPackageDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerOs(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_osinfo", BuildOsDbsyncRow(row, containerJson));
        }

        auto ifscan = ScanContainerInterfaces(pid);
        for (auto row : ifscan.interfaces) {
            ApplyIdentity(row, identity);
            emit("dbsync_network_iface", BuildInterfaceDbsyncRow(row, containerJson));
        }
        for (auto row : ifscan.addresses) {
            ApplyIdentity(row, identity);
            emit("dbsync_network_address", BuildNetworkAddressDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerProtocols(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_network_protocol", BuildProtocolDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerServices(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_services", BuildServiceDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerHardware(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_hwinfo", BuildHardwareDbsyncRow(row, containerJson));
        }
    }

    return baselined;
}

int ListContainers(const std::string& connector_socket_path, const ContainerIdSink& sink)
{
    int count = 0;

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        sink(identity.container_id);
        ++count;
    }

    return count;
}

} // namespace wazuh::container_baseline

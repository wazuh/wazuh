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

#include <chrono>
#include <optional>
#include <thread>
#include <utility>

namespace wazuh::container_baseline {

namespace {

// The container_instances IPC socket binds before its connectors finish their
// first snapshot (list is a pure store read with no cold-cache refresh), so a
// one-shot baseline at agent startup can see an "ok" but empty list while the
// store is still warming. Retry an empty list briefly; an actually-empty host
// only pays this once, at startup.
constexpr int kListRetryAttempts = 10;
constexpr auto kListRetryDelay = std::chrono::milliseconds{500};

// Every container currently tracked by the container_instances store, paired
// with its resolved identity. One IPC round trip to list, then one lookup per
// listed container. The list call gives us cgroup ids, so the lookup can resolve
// the richer metadata in the same module that owns it.
std::vector<ContainerIdentity> DiscoverContainers(const std::string& socket_path)
{
    wazuh::container_instances_client::ContainerInstancesClient client(socket_path);
    std::vector<ContainerIdentity> out;

    std::vector<wazuh::container_instances_client::ContainerRef> refs;
    for (int attempt = 1; attempt <= kListRetryAttempts; ++attempt)
    {
        refs = client.listContainers();
        if (!refs.empty() || attempt == kListRetryAttempts)
        {
            break;
        }
        std::this_thread::sleep_for(kListRetryDelay);
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

} // namespace wazuh::container_baseline

#include "container_baseline_scanner.hpp"

#include "baseline_rows.hpp"
#include "container_instances_client.hpp"
#include "interface_scanner.hpp"
#include "network_scanner.hpp"
#include "os_scanner.hpp"
#include "package_scanner.hpp"
#include "pid_resolver.hpp"
#include "process_scanner.hpp"
#include "rootfs_file_walker.hpp"
#include "user_scanner.hpp"

#include <json.hpp>

#include <chrono>
#include <thread>

namespace wazuh::container_baseline {

namespace {

constexpr int kOperationCreate = 0;

// The container_instances IPC socket binds before its connectors finish their
// first snapshot (list is a pure store read with no cold-cache refresh), so a
// one-shot baseline at agent startup can see an "ok" but empty list while the
// store is still warming. Retry an empty list briefly; an actually-empty host
// only pays this once, at startup.
constexpr int kListRetryAttempts = 10;
constexpr auto kListRetryDelay = std::chrono::milliseconds{500};

ContainerIdentity IdentityFromMetaJson(const std::string& container_id, const std::string& meta_json)
{
    ContainerIdentity id;
    id.container_id = container_id;

    auto j = nlohmann::json::parse(meta_json, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return id;

    if (const auto it = j.find("name"); it != j.end() && it->is_string()) {
        id.container_name = it->get<std::string>();
    }
    if (const auto it = j.find("image"); it != j.end() && it->is_string()) {
        id.image = it->get<std::string>();
    }
    if (const auto pod_it = j.find("pod"); pod_it != j.end() && pod_it->is_object()) {
        if (const auto it = pod_it->find("uid"); it != pod_it->end() && it->is_string()) {
            id.pod_uid = it->get<std::string>();
        }
        if (const auto it = pod_it->find("name"); it != pod_it->end() && it->is_string()) {
            id.pod_name = it->get<std::string>();
        }
        if (const auto it = pod_it->find("namespace"); it != pod_it->end() && it->is_string()) {
            id.k8s_namespace = it->get<std::string>();
        }
    }
    return id;
}

ContainerIdentity IdentityFromResolveJson(const std::string& container_id, const std::string& reply_json)
{
    ContainerIdentity id;
    id.container_id = container_id;

    const auto j = nlohmann::json::parse(reply_json, nullptr, false);
    if (j.is_discarded() || !j.is_object() || j.value("status", "") != "resolved")
    {
        return id;
    }

    const auto dataIt = j.find("data");
    if (dataIt == j.end() || !dataIt->is_object())
    {
        return id;
    }

    const auto& data = *dataIt;
    if (const auto it = data.find("container_name"); it != data.end() && it->is_string())
    {
        id.container_name = it->get<std::string>();
    }
    if (const auto it = data.find("image"); it != data.end() && it->is_string())
    {
        id.image = it->get<std::string>();
    }
    if (const auto it = data.find("pod_uid"); it != data.end() && it->is_string())
    {
        id.pod_uid = it->get<std::string>();
    }
    if (const auto it = data.find("pod_name"); it != data.end() && it->is_string())
    {
        id.pod_name = it->get<std::string>();
    }
    if (const auto it = data.find("namespace"); it != data.end() && it->is_string())
    {
        id.k8s_namespace = it->get<std::string>();
    }

    return id;
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
            out.push_back(ContainerIdentity{ref.containerId, {}, {}, {}, {}, {}});
            continue;
        }
        out.push_back(IdentityFromResolveJson(ref.containerId, lookup.json));
    }
    return out;
}

} // namespace

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

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        const auto pids = ResolvePidsForContainer(identity.container_id);
        if (pids.empty()) continue;

        ++baselined;

        for (auto row : ScanContainerProcesses(identity.container_id)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildProcessJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-processes", json, 1});
        }

        for (auto row : ScanContainerNetwork(identity.container_id)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildPortJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-ports", json, 1});
        }

        // M4 data classes (users/groups + packages) address the rootfs through
        // /proc/<pid>/root, so they need the live PID rather than the cgroup.
        const auto pid = pids.front();

        for (auto row : ScanContainerUsers(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildUserJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-users", json, 1});
        }

        for (auto row : ScanContainerGroups(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildGroupJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-groups", json, 1});
        }

        for (auto row : ScanContainerPackages(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildPackageJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-packages", json, 1});
        }

        // Remaining container-relevant syscollector classes: the image's OS
        // identity (rootfs os-release via the same /proc/<pid>/root family) and
        // the container netns' interfaces/addresses (setns hop — see
        // interface_scanner.hpp). Hardware/hotfixes/services/browser-extensions
        // are deliberately absent: hardware is the host's (already reported by
        // host syscollector), hotfixes are Windows-only, and services/browser
        // extensions don't exist in single-process container workloads.
        for (auto row : ScanContainerOs(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildOsJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-system", json, 1});
        }

        auto ifscan = ScanContainerInterfaces(pid);
        for (auto row : ifscan.interfaces) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildInterfaceJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-interfaces", json, 1});
        }
        for (auto row : ifscan.addresses) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildNetworkAddressJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-networks", json, 1});
        }
    }

    return baselined;
}

} // namespace wazuh::container_baseline

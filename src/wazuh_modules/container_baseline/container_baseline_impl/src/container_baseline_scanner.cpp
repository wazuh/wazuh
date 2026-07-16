#include "container_baseline_scanner.hpp"

#include "baseline_rows.hpp"
#include "container_connector_client.hpp"
#include "network_scanner.hpp"
#include "package_scanner.hpp"
#include "pid_resolver.hpp"
#include "process_scanner.hpp"
#include "rootfs_file_walker.hpp"
#include "user_scanner.hpp"

#include <json.hpp>

namespace wazuh::container_baseline {

namespace {

constexpr int kOperationCreate = 0;

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

// Every container currently tracked by the connector, paired with its resolved
// identity. One IPC round trip per container (list + one lookup each) — bounded
// by however many containers the node runs, same cost class container_connector
// itself already pays per eBPF-event lookup.
std::vector<ContainerIdentity> DiscoverContainers(const std::string& socket_path)
{
    wazuh::container_connector::ContainerConnectorClient client(socket_path);
    std::vector<ContainerIdentity> out;

    for (const auto& ref : client.ListContainers()) {
        const auto lookup = client.LookupByContainerId(ref.container_id);
        out.push_back(lookup.found ? IdentityFromMetaJson(ref.container_id, lookup.meta_json)
                                    : ContainerIdentity{ref.container_id, {}, {}, {}, {}, {}});
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
    }

    return baselined;
}

} // namespace wazuh::container_baseline

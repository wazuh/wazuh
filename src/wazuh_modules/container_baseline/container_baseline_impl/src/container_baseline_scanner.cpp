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
#include "rootfs_file_walker.hpp"
#include "service_scanner.hpp"
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

/// Parses container_instances' "resolve" reply "data" object (see
/// wire_protocol.hpp's recordToJson()) into the shared runtime context. Pod/
/// namespace/node/annotations/owner_refs are only ever present when the
/// module reports runtime == "kubernetes"; a Docker-origin container leaves
/// `kubernetes` unset entirely (event_schema.md's two-block rule).
ContainerContextPtr ContextFromResolveData(const nlohmann::json& data)
{
    auto ctx = std::make_shared<ContainerContext>();
    ctx->runtime       = data.value("runtime", "");
    ctx->name          = data.value("container_name", "");
    ctx->image         = data.value("image", "");
    ctx->image_digest  = data.value("image_digest", "");
    ctx->restart_count = data.value("restart_count", 0);

    if (const auto it = data.find("labels"); it != data.end() && it->is_object())
    {
        for (const auto& [key, value] : it->items())
        {
            if (value.is_string()) ctx->labels.emplace(key, value.get<std::string>());
        }
    }
    if (const auto it = data.find("network"); it != data.end() && it->is_array())
    {
        for (const auto& iface : *it)
        {
            NetworkEndpoint entry;
            entry.name = iface.value("name", "");
            entry.ip   = iface.value("ip", "");
            ctx->network.push_back(std::move(entry));
        }
    }
    if (const auto it = data.find("oci_mounts"); it != data.end() && it->is_array())
    {
        for (const auto& mount : *it)
        {
            OciMountEntry entry;
            entry.source      = mount.value("source", "");
            entry.destination = mount.value("destination", "");
            entry.read_only   = mount.value("ro", false);
            ctx->oci_mounts.push_back(std::move(entry));
        }
    }

    if (ctx->runtime == "kubernetes")
    {
        KubernetesContext k8s;
        k8s.pod_uid       = data.value("pod_uid", "");
        k8s.pod_name      = data.value("pod_name", "");
        k8s.k8s_namespace = data.value("namespace", "");
        k8s.node_name     = data.value("node_name", "");

        if (const auto it = data.find("annotations"); it != data.end() && it->is_object())
        {
            for (const auto& [key, value] : it->items())
            {
                if (value.is_string()) k8s.annotations.emplace(key, value.get<std::string>());
            }
        }
        if (const auto it = data.find("owner_refs"); it != data.end() && it->is_array())
        {
            for (const auto& owner : *it)
            {
                OwnerReference ref;
                ref.kind = owner.value("kind", "");
                ref.name = owner.value("name", "");
                ref.uid  = owner.value("uid", "");
                k8s.owner_refs.push_back(std::move(ref));
            }
        }

        ctx->kubernetes = std::move(k8s);
    }

    return ctx;
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

    id.context = ContextFromResolveData(*dataIt);
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
            out.push_back(ContainerIdentity{ref.containerId, nullptr});
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

        // Image OS identity (rootfs os-release via the /proc/<pid>/root family).
        for (auto row : ScanContainerOs(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildOsJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-system", json, 1});
        }

        // Container netns interfaces/addresses (setns hop — see interface_scanner.hpp).
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

        // Default routes (protocols) from the container netns' /proc/<pid>/net/route.
        for (auto row : ScanContainerProtocols(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildProtocolJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-protocols", json, 1});
        }

        // systemd services from the rootfs unit files (static view; runtime state
        // needs the container's own systemd over D-Bus — see service_scanner.hpp).
        for (auto row : ScanContainerServices(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildServiceJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-services", json, 1});
        }

        // Virtual hardware: the container's cgroup resource envelope (memory.max /
        // cpu.max) mapped onto the hardware schema; cpu name/speed are the shared
        // host silicon. Hotfixes (Windows-only) and browser-extensions (no browser
        // in a server container) are the only host collectors left uncovered.
        for (auto row : ScanContainerHardware(pid)) {
            ApplyIdentity(row, identity);
            auto [id, json] = BuildHardwareJson(row);
            sink(EmittedRow{id, kOperationCreate, "wazuh-states-inventory-hardware", json, 1});
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

} // namespace wazuh::container_baseline

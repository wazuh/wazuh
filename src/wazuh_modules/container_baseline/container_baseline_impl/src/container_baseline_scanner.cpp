#include "container_baseline_scanner.hpp"

#include "baseline_rows.hpp"
#include "container_instances_client.hpp"
#include "container_scope.hpp"
#include "hardware_scanner.hpp"
#include "image_content_cache.hpp"
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

#include <atomic>
#include <chrono>
#include <thread>
#include <unordered_set>
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

/// Parses one container_instances record (see wire_protocol.hpp's
/// recordToJson()) into the shared runtime context. Pod/namespace/node/
/// annotations/owner_refs are only ever present when the module reports
/// runtime == "kubernetes"; a Docker-origin container leaves `kubernetes` unset
/// entirely (event_schema.md's two-block rule).
ContainerContextPtr ContextFromRecord(const nlohmann::json& data)
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

// Every container currently tracked by the container_instances store, paired
// with its resolved identity.
//
// ONE IPC round trip total: the `list` reply already carries each container's
// full record (wire_protocol.hpp builds it with the same recordToJson() that
// `resolve` uses for its "data" object), so there is no reason to follow up
// with a per-container `resolve`. Each round trip is its own
// connect/send/recv/close against a 2-worker server with a 1 s timeout, so
// dropping the follow-ups takes a 100-container node from 101 connections per
// baseline to 1.
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

    out.reserve(refs.size());
    for (const auto& ref : refs)
    {
        ContainerContextPtr ctx;
        if (ref.record.is_object())
        {
            ctx = ContextFromRecord(ref.record);
        }
        out.push_back(ContainerIdentity{ref.containerId, std::move(ctx)});
    }
    return out;
}

/// Everything one baseline run needs to know about the host, computed once
/// instead of once per container per scanner.
///
/// Before this existed, resolving a container's PIDs meant a full /proc walk
/// (reading /proc/<pid>/cgroup for every PID), and it was done once by the
/// orchestrator plus once inside ScanContainerProcesses plus once inside
/// ScanContainerNetwork — three walks per container. On a node with 100
/// containers and 2000 processes that is 300 walks and ~600k file reads per
/// baseline cycle, none of which produces a row. One sweep replaces all of it.
struct RunContext
{
    PidIndex                        pids;
    std::unordered_set<std::string> shared_netns;
    ImageContentCache               image_content;

    static RunContext Build()
    {
        RunContext rc;
        rc.pids         = PidIndex::Build();
        rc.shared_netns = SharedNetnsContainers(rc.pids.all());
        return rc;
    }

    [[nodiscard]] bool netnsShared(const std::string& container_id) const
    {
        return shared_netns.find(container_id) != shared_netns.end();
    }
};

} // namespace

int RunFimDbsyncBaseline(const std::string&                connector_socket_path,
                          const std::vector<MonitoredPath>& paths,
                          const DbsyncRowSink&              sink,
                          const ContainerStatusSink&        status_sink,
                          const std::function<void()>&      rate_limit)
{
    int baselined = 0;

    const auto run = RunContext::Build();

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        const auto& pids = run.pids.pidsFor(identity.container_id);
        if (pids.empty()) continue; // no live PID — nothing to address the rootfs with (yet).

        ++baselined;
        const auto pid = pids.front();
        const auto containerJson = BuildContainerContextJson(identity.container_id, identity.context);

        // A walk that hit its row cap, or whose configured path doesn't exist in
        // this image, produces a SUBSET of the container's files. Absence must
        // not then be read as deletion, so the incompleteness is reported to the
        // caller rather than discarded.
        bool partial = false;

        for (const auto& mp : paths) {
            const auto walk = WalkContainerPath(pid, mp.internal_path, mp.recursion_level,
                                                 mp.max_files, mp.max_hash_bytes,
                                                 identity.context, mp.hashes, rate_limit);
            partial = partial || walk.truncated || walk.root_missing;

            for (auto row : walk.rows) {
                ApplyIdentity(row, identity);
                sink(DbsyncRow{identity.container_id, "file_entry",
                               BuildFimFileDbsyncRow(row, containerJson)});
            }
        }

        // A PID that exited partway through the walk makes every subsequent
        // read fail, so the row set is a subset of the container's files even
        // though nothing reported an error. Treat that as an incomplete scan.
        if (!RootfsStillAddressable(pid)) {
            partial = true;
        }

        if (status_sink) {
            status_sink(ContainerStatus{identity.container_id, partial});
        }
    }

    return baselined;
}

int RunSyscollectorDbsyncBaseline(const std::string&         connector_socket_path,
                                  const DbsyncRowSink&       sink,
                                  const ContainerStatusSink& status_sink)
{
    int baselined = 0;

    auto run = RunContext::Build();

    for (const auto& identity : DiscoverContainers(connector_socket_path)) {
        const auto& pids = run.pids.pidsFor(identity.container_id);
        if (pids.empty()) continue;

        ++baselined;

        const auto pid   = pids.front();
        const auto scope = DetectContainerScope(pid);

        // Context blob serialized once per container; every row carries it in
        // its container_json column so DELETED events stay self-contained.
        const auto containerJson = BuildContainerContextJson(identity.container_id, identity.context);
        const auto emit = [&](const std::string& table, std::string json) {
            sink(DbsyncRow{identity.container_id, table, std::move(json)});
        };

        for (auto row : ScanContainerProcesses(identity.container_id, pids)) {
            ApplyIdentity(row, identity);
            emit("dbsync_processes", BuildProcessDbsyncRow(row, containerJson));
        }

        // Network-namespace-scoped classes. ScanContainerNetwork itself declines
        // to report anything when the netns is the host's, and reports only
        // attributable sockets when a pod shares the netns.
        for (auto row : ScanContainerNetwork(identity.container_id, pids, scope,
                                             run.netnsShared(identity.container_id))) {
            ApplyIdentity(row, identity);
            emit("dbsync_ports", BuildPortDbsyncRow(row, containerJson));
        }

        // Users, groups, packages and the OS record are image-layer content, so
        // replicas of one image would otherwise be parsed once per replica —
        // and for RPM that means copying the whole rpmdb to a temp dir each
        // time. Reuse is keyed by image digest AND validated by a stat()
        // fingerprint of the backing files, so a container that modified any of
        // them in its writable layer is still scanned for real.
        const auto imageDigest = identity.context ? identity.context->image_digest : std::string {};
        const auto fingerprint = FingerprintImageSources(pid);

        // Holds the rows when this container is not cacheable (no resolved
        // image digest), so there is exactly one scan path either way.
        ImageContentCache::Entry standalone;

        const auto* content = run.image_content.find(imageDigest, fingerprint);

        if (content == nullptr) {
            ImageContentCache::Entry fresh;
            fresh.fingerprint = fingerprint;
            fresh.users       = ScanContainerUsers(pid);
            fresh.groups      = ScanContainerGroups(pid);
            fresh.packages    = ScanContainerPackages(pid);
            fresh.os          = ScanContainerOs(pid);

            if (imageDigest.empty()) {
                standalone = std::move(fresh);
                content    = &standalone;
            } else {
                run.image_content.store(imageDigest, std::move(fresh));
                content = run.image_content.find(imageDigest, fingerprint);
            }
        }

        for (auto row : content->users) {
            ApplyIdentity(row, identity);
            emit("dbsync_users", BuildUserDbsyncRow(row, containerJson));
        }

        for (auto row : content->groups) {
            ApplyIdentity(row, identity);
            emit("dbsync_groups", BuildGroupDbsyncRow(row, containerJson));
        }

        for (auto row : content->packages) {
            ApplyIdentity(row, identity);
            emit("dbsync_packages", BuildPackageDbsyncRow(row, containerJson));
        }

        for (auto row : content->os) {
            ApplyIdentity(row, identity);
            emit("dbsync_osinfo", BuildOsDbsyncRow(row, containerJson));
        }

        auto ifscan = ScanContainerInterfaces(pid, scope);
        for (auto row : ifscan.interfaces) {
            ApplyIdentity(row, identity);
            emit("dbsync_network_iface", BuildInterfaceDbsyncRow(row, containerJson));
        }
        for (auto row : ifscan.addresses) {
            ApplyIdentity(row, identity);
            emit("dbsync_network_address", BuildNetworkAddressDbsyncRow(row, containerJson));
        }

        // Routes come from /proc/<pid>/net/route, which is netns-relative — so
        // on a host-network container it is the NODE's routing table and must
        // not be attributed here either.
        if (!scope.netCollapsedToHost()) {
            for (auto row : ScanContainerProtocols(pid)) {
                ApplyIdentity(row, identity);
                emit("dbsync_network_protocol", BuildProtocolDbsyncRow(row, containerJson));
            }
        }

        for (auto row : ScanContainerServices(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_services", BuildServiceDbsyncRow(row, containerJson));
        }

        for (auto row : ScanContainerHardware(pid)) {
            ApplyIdentity(row, identity);
            emit("dbsync_hwinfo", BuildHardwareDbsyncRow(row, containerJson));
        }

        if (status_sink) {
            ContainerStatus status{identity.container_id, false};

            // The rootfs-backed classes (users, groups, packages, os, services)
            // all read through /proc/<pid>/root, so a PID that exited mid-scan
            // silently truncates them the same way it does the FIM walk.
            status.partial = !RootfsStillAddressable(pid);

            // The two network flags are reported separately rather than folded
            // into `partial` because they say precisely WHICH data classes are
            // absent, letting the consumer suppress delete detection for just
            // those tables. Folding them in would stall deletions for all
            // eleven — and on a host without CAP_SYS_ADMIN that would mean
            // stale rows accumulating forever.
            status.netns_host_scoped = scope.netCollapsedToHost();
            status.netns_unreadable  = ifscan.setns_failed;
            status_sink(status);
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

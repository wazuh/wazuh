#include "container_baseline_scanner.hpp"

#include "baseline_rows.hpp"
#include "container_instances_client.hpp"
#include "container_scope.hpp"
#include "hardware_scanner.hpp"
#include "image_content_cache.hpp"
#include "internal_path_guard.hpp"
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

// ...and the retry-on-empty is additionally confined to the FIRST discovery of
// the process, which is the only moment the warm-up race can happen. Without
// this, a node that genuinely runs no containers never latches
// g_everSawContainers and so pays the full retry cost on every recurring scan,
// forever — the exact unbounded latency the comment above warns about.
std::atomic<bool> g_warmupWindowClosed{false};

// A connector that has answered can still be mid-enumeration: it reports a
// well-formed, non-empty, but INCOMPLETE list. That is not hypothetical — on a
// real node FIM baselined 3 of 4 containers at startup and the fourth (a Docker
// container) never appeared, because Docker's connector had not finished its
// first snapshot when the one-shot baseline ran
// (spike-37533/startup-race-solutions-and-edge-cases.md, finding #2).
//
// So once a list is in hand, poll again until two consecutive polls report the
// same SET of container ids — sets, not counts, so that one container starting
// as another stops cannot look like quiescence. Bounded, and latched once
// quiescence is genuinely observed so the cost is paid at most once per process.
constexpr int kQuiescenceRetryAttempts = 5;
std::atomic<bool> g_containersStable{false};

std::unordered_set<std::string>
ContainerIdSet(const std::vector<wazuh::container_instances_client::ContainerRef>& refs)
{
    std::unordered_set<std::string> ids;
    ids.reserve(refs.size());
    for (const auto& ref : refs)
    {
        ids.insert(ref.containerId);
    }
    return ids;
}

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
std::vector<ContainerIdentity> DiscoverContainers(const std::string& socket_path, bool* reachable = nullptr)
{
    wazuh::container_instances_client::ContainerInstancesClient client(socket_path);
    std::vector<ContainerIdentity> out;

    if (reachable != nullptr)
    {
        *reachable = false;
    }

    std::vector<wazuh::container_instances_client::ContainerRef> refs;
    bool answered = false;

    // Phase 1 — get an answer, and give a still-warming connector time to have
    // something to report.
    const bool warmupWindow = !g_everSawContainers.load() && !g_warmupWindowClosed.load();
    const int attempts = warmupWindow ? kListRetryAttempts : 1;
    for (int attempt = 1; attempt <= attempts; ++attempt)
    {
        bool polled = false;
        auto listed = client.listContainers(&polled);
        if (polled)
        {
            answered = true;
            refs = std::move(listed);
        }

        // Two different reasons to poll again, and they must not be conflated:
        //
        //   not answered   the connector is unreachable. Retrying may find it.
        //   answered empty the connector is reachable but may not have finished
        //                  its first enumeration, in which case an empty list is
        //                  a truthful "nothing yet" rather than "nothing".
        //
        // The difference matters for DELETIONS, not for how long to wait: only
        // `answered` gates the caller's stale sweep (see the header), and an
        // empty list from a connector that has answered is still authoritative
        // once the warm-up window has closed.
        if ((answered && !refs.empty()) || attempt == attempts)
        {
            break;
        }
        std::this_thread::sleep_for(kListRetryDelay);
    }

    g_warmupWindowClosed.store(true);

    if (reachable != nullptr)
    {
        *reachable = answered;
    }

    if (!refs.empty())
    {
        g_everSawContainers.store(true);
    }

    // Phase 2 — quiescence. Only meaningful once there is a list to compare.
    if (!refs.empty() && !g_containersStable.load())
    {
        auto lastIds = ContainerIdSet(refs);
        bool stable = false;

        for (int attempt = 1; attempt <= kQuiescenceRetryAttempts; ++attempt)
        {
            std::this_thread::sleep_for(kListRetryDelay);

            bool polled = false;
            auto nextRefs = client.listContainers(&polled);
            if (!polled)
            {
                // The connector went away mid-check. Keep the last list that it
                // did answer with rather than adopting a failed poll's empty
                // one, and leave the latch clear so the next run re-checks.
                break;
            }

            auto nextIds = ContainerIdSet(nextRefs);
            if (nextIds == lastIds)
            {
                stable = true;
                break;
            }
            refs = std::move(nextRefs);
            lastIds = std::move(nextIds);
        }

        if (stable)
        {
            g_containersStable.store(true);
        }
        // Otherwise: the attempts ran out without two consecutive polls
        // agreeing. Proceed with whatever the last answered poll returned
        // rather than blocking this run indefinitely, and deliberately leave
        // g_containersStable clear so the next call checks again instead of
        // accepting a possibly-incomplete list for the rest of the process.
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

} // namespace

int RunFimDbsyncBaselineFrom(const ContainerDiscoverer&        discover,
                              const PidIndex&                   pidIndex,
                              const std::vector<MonitoredPath>& paths,
                              const DbsyncRowSink&              sink,
                              const ContainerStatusSink&        status_sink,
                              const std::function<void()>&      rate_limit)
{
    int baselined = 0;

    for (const auto& identity : discover()) {
        const auto& pids = pidIndex.pidsFor(identity.container_id);
        if (pids.empty()) continue; // no live PID — nothing to address the rootfs with (yet).

        // The PID list is a snapshot, so some entries may already have exited.
        // Pick one whose rootfs is addressable rather than whichever happened to
        // be first.
        const auto pid = SelectAddressablePid(pids);
        if (pid == 0) continue; // every candidate has gone; same as "no live PID"

        ++baselined;
        const auto containerJson = BuildContainerContextJson(identity.container_id, identity.context);

        // A walk that hit its row cap, or whose root could not be examined,
        // produces a SUBSET of the container's files, and absence must not then
        // be read as deletion. A root that is simply ABSENT from the image is a
        // different fact and is counted separately: the walk did look, so
        // suppressing delete detection for it is C24 — a static condition that
        // switched deletions off for that container permanently. See D17.
        ContainerStatus status;
        status.container_id = identity.container_id;

        for (const auto& mp : paths) {
            const auto walk = WalkContainerPath(pid, mp.internal_path, mp.recursion_level,
                                                 mp.max_files, mp.max_hash_bytes,
                                                 identity.context, mp.hashes, rate_limit);

            if (walk.truncated) status.row_cap_hit = true;
            if (walk.root_unreadable) status.rootfs_unreadable = true;

            if (walk.root_missing) {
                ++status.roots_missing;
            } else if (!walk.root_unreadable) {
                ++status.roots_scanned;
            }

            for (auto row : walk.rows) {
                ApplyIdentity(row, identity);
                sink(DbsyncRow{identity.container_id, "file_entry",
                               BuildFimFileDbsyncRow(row, containerJson)});
            }
        }

        // A PID that exited partway through makes every subsequent read fail,
        // so the row set is a subset of the container's files even though
        // nothing reported an error.
        //
        // Deliberately NOT retried on another PID: doing so means buffering the
        // whole container before emitting anything (otherwise a retry would
        // republish rows already sent), and one container's files can be tens of
        // thousands of rows — which is the node-scale buffering that streaming
        // exists to avoid. Reporting the scan as partial is already safe (the
        // consumer suppresses delete detection) and the next cycle completes it.
        if (!RootfsStillAddressable(pid)) {
            status.rootfs_unreadable = true;
        }

        status.partial = status.row_cap_hit || status.rootfs_unreadable || status.paths_rejected;

        if (status_sink) {
            status_sink(status);
        }
    }

    return baselined;
}

int RunFimDbsyncBaselineForContainerFrom(const ContainerDiscoverer&        discover,
                                          const std::string&                container_id,
                                          const PidIndex&                   pidIndex,
                                          const std::vector<MonitoredPath>& paths,
                                          const DbsyncRowSink&              sink,
                                          const ContainerStatusSink&        status_sink,
                                          const std::function<void()>&      rate_limit)
{
    if (container_id.empty()) return 0;

    std::vector<ContainerIdentity> selected;
    for (auto& identity : discover()) {
        if (identity.container_id == container_id) {
            selected.push_back(std::move(identity));
            break;
        }
    }

    // Not in the connector's list. Deliberately 0 and not an error: "gone" is
    // decided by the whole-node stale sweep, which compares a REACHABLE list
    // against what is stored. A single-container call has no standing to
    // conclude anything about deletion from one absence.
    if (selected.empty()) return 0;

    // These paths may not come from agent configuration — in the eBPF consumer
    // they arrive in kernel events emitted inside the container. Reject rather
    // than normalise: rewriting "/etc/../x" into "/x" would silently scan
    // something other than what was asked for. See internal_path_guard.hpp.
    std::vector<MonitoredPath> safe;
    safe.reserve(paths.size());
    bool rejected = false;

    for (const auto& mp : paths) {
        if (IsSafeInternalPath(mp.internal_path)) {
            safe.push_back(mp);
        } else {
            rejected = true;
        }
    }

    // No usable path means nothing was baselined, and saying so matters: the
    // alternative is returning 1 for a walk that emitted no rows, which a
    // caller doing delete detection would read as "this container has no files"
    // and act on. Covers both "every path was rejected" and "none were given".
    if (safe.empty()) return 0;

    ContainerStatusSink guarded = status_sink;

    if (rejected && status_sink) {
        // A dropped path makes the row set a subset of what was asked for —
        // exactly what `partial` exists to say — so delete detection is
        // suppressed instead of the rejection passing unnoticed. Reported as
        // its own fact too, so a consumer can tell a rejected path apart from a
        // capped walk (D17).
        guarded = [status_sink](const ContainerStatus& status) {
            ContainerStatus forced = status;
            forced.paths_rejected  = true;
            forced.partial         = true;
            status_sink(forced);
        };
    }

    return RunFimDbsyncBaselineFrom([&selected]() { return selected; },
                                    pidIndex, safe, sink, guarded, rate_limit);
}

int RunSyscollectorDbsyncBaselineFrom(const ContainerDiscoverer& discover,
                                       const PidIndex&            pidIndex,
                                       const DbsyncRowSink&       sink,
                                       const ContainerStatusSink& status_sink)
{
    int baselined = 0;

    // Per-run state that is not the PID index: the image-content cache, and the
    // shared-netns grouping derived from the index.
    ImageContentCache  imageContent;
    const auto         sharedNetns = SharedNetnsContainers(pidIndex.all());

    for (const auto& identity : discover()) {
        const auto& pids = pidIndex.pidsFor(identity.container_id);
        if (pids.empty()) continue;

        const auto pid = SelectAddressablePid(pids);
        if (pid == 0) continue; // every candidate has gone; same as "no live PID"

        ++baselined;

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
        const bool netnsShared = sharedNetns.find(identity.container_id) != sharedNetns.end();

        for (auto row : ScanContainerNetwork(identity.container_id, pids, scope, netnsShared)) {
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

        const auto* content = imageContent.find(imageDigest, fingerprint);

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
                imageContent.store(imageDigest, std::move(fresh));
                content = imageContent.find(imageDigest, fingerprint);
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
            ContainerStatus status;
            status.container_id = identity.container_id;

            // The rootfs-backed classes (users, groups, packages, os, services)
            // all read through /proc/<pid>/root, so a PID that exited mid-scan
            // silently truncates them the same way it does the FIM walk.
            status.rootfs_unreadable = !RootfsStillAddressable(pid);
            status.partial           = status.rootfs_unreadable;

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

// The production entry points: one /proc sweep, then the shared core.
//
// The sweep is what the per-container /proc walks used to be — the orchestrator,
// the process scanner and the network scanner each walked all of /proc for every
// container, so a node with 100 containers and 2000 processes did 300 walks
// (~600k file reads) per cycle without producing a row.

int RunFimDbsyncBaseline(const std::string&                connector_socket_path,
                          const std::vector<MonitoredPath>& paths,
                          const DbsyncRowSink&              sink,
                          const ContainerStatusSink&        status_sink,
                          const std::function<void()>&      rate_limit)
{
    const auto pids = PidIndex::Build();

    return RunFimDbsyncBaselineFrom(
        [&connector_socket_path]() { return DiscoverContainers(connector_socket_path); },
        pids, paths, sink, status_sink, rate_limit);
}

int RunFimDbsyncBaselineForContainer(const std::string&                connector_socket_path,
                                      const std::string&                container_id,
                                      const std::vector<MonitoredPath>& paths,
                                      const DbsyncRowSink&              sink,
                                      const ContainerStatusSink&        status_sink,
                                      const std::function<void()>&      rate_limit)
{
    if (container_id.empty()) return 0;

    bool       reachable  = false;
    const auto identities = DiscoverContainers(connector_socket_path, &reachable);

    // -1 before anything else. An unreachable connector reports zero containers,
    // so proceeding would make "I could not ask" indistinguishable from "this
    // container is gone" — the C15 failure, scoped to one container.
    if (!reachable) return -1;

    // One /proc sweep per call. Measured cost, not a guess: on a node with N
    // live processes this is N reads of /proc/<pid>/cgroup, and a re-walk storm
    // pays it once per container per batch. The cheaper answer when it matters
    // is reading the cgroup's own cgroup.procs, which needs the cgroup PATH
    // while the eBPF consumer holds only its inode — see
    // 13-container-baseline-api-plan.md §13.6.
    const auto pids = PidIndex::FromMap({{container_id, ResolvePidsForContainer(container_id)}});

    return RunFimDbsyncBaselineForContainerFrom([&identities]() { return identities; },
                                                container_id, pids, paths, sink, status_sink, rate_limit);
}

int RunSyscollectorDbsyncBaseline(const std::string&         connector_socket_path,
                                  const DbsyncRowSink&       sink,
                                  const ContainerStatusSink& status_sink)
{
    const auto pids = PidIndex::Build();

    return RunSyscollectorDbsyncBaselineFrom(
        [&connector_socket_path]() { return DiscoverContainers(connector_socket_path); },
        pids, sink, status_sink);
}

int ListContainers(const std::string& connector_socket_path, const ContainerIdSink& sink)
{
    bool reachable = false;
    const auto identities = DiscoverContainers(connector_socket_path, &reachable);

    // -1, not 0. Callers use this list as the authority on what still exists
    // and delete the rows of everything absent from it, so an unreachable
    // connector must NOT present as "no containers exist" — that would delete
    // every container's stored rows on a momentary blip and re-create them on
    // the next cycle.
    if (!reachable)
    {
        return -1;
    }

    int count = 0;

    for (const auto& identity : identities) {
        sink(identity.container_id);
        ++count;
    }

    return count;
}

} // namespace wazuh::container_baseline

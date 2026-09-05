#pragma once

#include "hash_helper.hpp"
#include "pid_resolver.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief A single `<directories tags="container">`-style entry: an in-container
/// path to walk, independent of any one syscheck.h type so this module has no
/// compile-time dependency on syscheckd's config headers. The FIM call site
/// (src/syscheckd/src/ebpf/src/container_baseline_fim_bridge.c) is responsible
/// for translating syscheck.directories into a vector of these.
struct MonitoredPath
{
    std::string   internal_path;
    int           recursion_level{-1};
    size_t        max_files{20000};      // NFR3-style hard cap; see rootfs_file_walker.hpp.
    size_t        max_hash_bytes{104857600}; // Files LARGER than this are not hashed at all.
    HashSelection hashes{};              // Which digests to compute (default: all three).
};

/// @brief One baseline row rendered in syscollector's dbsync_* column format
/// (Option A: baseline through the host event flow). `json` is a flat object of
/// dbsync columns (including container_id/container_json); `table` is the
/// dbsync table name ("dbsync_processes", ...). The consumer (syscollector)
/// groups rows per container per table and pushes them through per-container
/// scoped DBSync transactions so the existing notifyChange/processEvent
/// pipeline emits the deltas.
struct DbsyncRow
{
    std::string container_id;
    std::string table;
    std::string json;
};

using DbsyncRowSink = std::function<void(const DbsyncRow&)>;

/// @brief Per-container outcome, reported after all of that container's rows
/// have been emitted.
///
/// This exists because "produced no row for X" and "X is gone" are different
/// facts, and conflating them makes a baseline emit false deletions. A scan
/// that was capped, whose configured path is absent from the image, or whose
/// namespace could not be entered, has produced a SUBSET of the container's
/// true state — so the consumer must upsert what it received without treating
/// the remainder as deleted.
struct ContainerStatus
{
    std::string container_id;

    /// The scan is known to be incomplete: a row cap was hit, a configured
    /// path was missing, or a namespace could not be read. Consumers MUST NOT
    /// derive deletions from absent rows for this container.
    bool partial{false};

    /// The container shares the host's network namespace, so no
    /// network-namespace-scoped rows (ports, interfaces, addresses, routes)
    /// were attributed to it. Not a failure — the rows genuinely are not the
    /// container's — but the consumer must not read their absence as deletion
    /// either.
    bool netns_host_scoped{false};

    /// The container's network namespace could not be entered (typically a
    /// missing CAP_SYS_ADMIN). Worth logging: interface/address rows are absent
    /// for an environmental reason, not because the container has none.
    bool netns_unreadable{false};
};

using ContainerStatusSink = std::function<void(const ContainerStatus&)>;

/// @brief Run the FIM file baseline for every container currently known to
/// container_instances, over every configured MonitoredPath, emitting raw
/// file_entry dbsync rows.
///
/// The consumer (syscheckd's container_baseline_fim.cpp) groups rows per
/// container, opens a per-container scoped fim_db_transaction_start, and lets
/// the existing transaction_callback compute deltas and emit events.
///
/// @param connector_socket_path Unix socket path of the container_instances IPC
///                              server (see container_instances_client.hpp).
/// @param paths Monitored in-container paths.
/// @param sink Invoked once per row.
/// @param status_sink Optional; invoked once per scanned container with its
///                    completeness. Pass an empty function to ignore.
/// @param rate_limit Optional; invoked once per file before it is hashed so the
///                   caller can throttle (FIM passes check_max_fps()). This is
///                   the NFR3 files-per-second bound; empty means no limit.
/// @return Number of containers that were baselined (i.e. had at least one live
///         PID resolvable). Containers known to the connector but with no live
///         PID are skipped and NOT counted — compare against ListContainers()
///         to tell "stopped" apart from "gone".
int RunFimDbsyncBaseline(const std::string&                connector_socket_path,
                          const std::vector<MonitoredPath>& paths,
                          const DbsyncRowSink&              sink,
                          const ContainerStatusSink&        status_sink = {},
                          const std::function<void()>&      rate_limit = {});

/// @brief Run the Syscollector inventory baseline (processes, ports, users,
/// groups, packages, os, interfaces, addresses, routes, services, hardware) for
/// every container currently known to container_instances, emitting raw dbsync
/// rows. Same return semantics as RunFimDbsyncBaseline().
int RunSyscollectorDbsyncBaseline(const std::string&         connector_socket_path,
                                  const DbsyncRowSink&       sink,
                                  const ContainerStatusSink& status_sink = {});

/// @brief Container identity as the orchestrator consumes it. Declared here
/// (rather than only in baseline_rows.hpp) so the seam below can be described
/// without pulling in the row builders.
struct ContainerIdentity;

/// @brief Seam replacing the IPC discovery step: returns the containers to
/// baseline. Production code uses the socket-path entry points above, which
/// supply a discoverer backed by container_instances; tests supply their own so
/// the orchestrator's lifecycle behaviour can be exercised without a running
/// connector.
using ContainerDiscoverer = std::function<std::vector<ContainerIdentity>()>;

/// @brief FIM baseline over an explicit container list and PID index.
///
/// Same behaviour as RunFimDbsyncBaseline(); exists so the ordering and
/// completeness contracts the consumers depend on can be tested directly:
/// a container's rows are emitted contiguously and are followed by exactly one
/// status callback for that container, and a container with no live PID is
/// skipped without a status and without being counted.
int RunFimDbsyncBaselineFrom(const ContainerDiscoverer&        discover,
                              const PidIndex&                   pids,
                              const std::vector<MonitoredPath>& paths,
                              const DbsyncRowSink&              sink,
                              const ContainerStatusSink&        status_sink = {},
                              const std::function<void()>&      rate_limit = {});

/// @brief FIM baseline for ONE container, over the paths the caller supplies.
///
/// Serves both actions the eBPF reconcile consumer (#37532) needs, differing
/// only in what it passes as `paths`:
///   - re-walk a container: the configured monitored paths;
///   - re-read specific files: one MonitoredPath per file. No special mode is
///     needed — WalkContainerPath() emits exactly one row when `internal_path`
///     names a non-directory (rootfs_file_walker.cpp), at any recursion level.
///
/// **Paths are validated** with IsSafeInternalPath() and rejected ones are
/// dropped, because unlike every other entry point here these may come from
/// outside the agent's own configuration — in the eBPF consumer they arrive in
/// kernel events emitted by processes inside the container. A rejection forces
/// the scan to be reported partial, so it suppresses delete detection rather
/// than passing unnoticed.
///
/// @return  1  baselined (a live, addressable PID was found);
///          0  nothing was baselined — the container is unknown to the
///             connector, has no resolvable PID, or was given no usable path.
///             Its stored rows must be KEPT;
///         -1  the connector could not be reached. Its stored rows must be KEPT.
///
/// The tri-state matters and is why this does not return a count like the
/// whole-node entry points do. Those can lean on ListContainers()' own -1 to
/// tell "stopped" from "could not ask"; a single-container caller has no such
/// second signal, and collapsing 0 and -1 would let a momentary connector blip
/// look exactly like "this container has no files any more" — the C15 mass
/// false-delete, one container at a time.
int RunFimDbsyncBaselineForContainer(const std::string&                connector_socket_path,
                                      const std::string&                container_id,
                                      const std::vector<MonitoredPath>& paths,
                                      const DbsyncRowSink&              sink,
                                      const ContainerStatusSink&        status_sink = {},
                                      const std::function<void()>&      rate_limit = {});

/// @brief Single-container FIM baseline over an explicit container list and PID
/// index, so the selection, path validation and partial-reporting behaviour can
/// be tested without a running connector. See RunFimDbsyncBaselineForContainer()
/// for the contract; this variant cannot report -1, since reachability is the
/// caller's to establish.
int RunFimDbsyncBaselineForContainerFrom(const ContainerDiscoverer&        discover,
                                          const std::string&                container_id,
                                          const PidIndex&                   pids,
                                          const std::vector<MonitoredPath>& paths,
                                          const DbsyncRowSink&              sink,
                                          const ContainerStatusSink&        status_sink = {},
                                          const std::function<void()>&      rate_limit = {});

/// @brief Syscollector inventory baseline over an explicit container list and
/// PID index. See RunFimDbsyncBaselineFrom().
int RunSyscollectorDbsyncBaselineFrom(const ContainerDiscoverer& discover,
                                       const PidIndex&            pids,
                                       const DbsyncRowSink&       sink,
                                       const ContainerStatusSink& status_sink = {});

using ContainerIdSink = std::function<void(const std::string&)>;

/// @brief Lists every container currently known to container_instances,
/// independent of whether it has a resolvable live PID right now — unlike the
/// Run*Baseline() functions above, a momentarily-stopped container (known,
/// but no live PID) is still reported here. Callers that need to tell
/// "stopped" apart from "gone" should compare this list against a
/// Run*Baseline() call's output rather than treating "produced no rows" as
/// "removed".
///
/// @return Number of containers reported through `sink`, or **-1 when the
///         connector could not be reached or answered malformed**. Callers
///         MUST check for -1 before using the list to authorise deletions: a
///         failed query yields an empty list, and treating that as "nothing
///         exists" deletes every container's stored rows on a momentary
///         connector blip.
int ListContainers(const std::string& connector_socket_path, const ContainerIdSink& sink);

} // namespace wazuh::container_baseline

#pragma once

#include "hash_helper.hpp"

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

using ContainerIdSink = std::function<void(const std::string&)>;

/// @brief Lists every container currently known to container_instances,
/// independent of whether it has a resolvable live PID right now — unlike the
/// Run*Baseline() functions above, a momentarily-stopped container (known,
/// but no live PID) is still reported here. Callers that need to tell
/// "stopped" apart from "gone" should compare this list against a
/// Run*Baseline() call's output rather than treating "produced no rows" as
/// "removed".
/// @return Number of containers reported through `sink`.
int ListContainers(const std::string& connector_socket_path, const ContainerIdSink& sink);

} // namespace wazuh::container_baseline

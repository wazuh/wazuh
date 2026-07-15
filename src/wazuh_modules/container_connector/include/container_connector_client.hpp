#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifdef WIN_EXPORT
#    define EXPORTED __declspec(dllexport)
#  else
#    define EXPORTED __declspec(dllimport)
#  endif
#elif __GNUC__ >= 4
#  define EXPORTED __attribute__((visibility("default")))
#else
#  define EXPORTED
#endif

namespace wazuh::container_connector {

/// @brief Result of a cache lookup against the container-connector module.
///
/// `found == false`: no record for the given identifier (expected when the kernel
///                   emits an event for a host process or a container we don't track).
/// `found == true` : `meta_json` holds the raw JSON line returned by the server,
///                   without surrounding `{"ok":true,"meta":...}` envelope.
///                   Consumers parse it with the JSON lib of their choice.
struct EXPORTED LookupResult
{
    bool        found{false};
    std::string meta_json;
};

/// @brief Lightweight reference to a tracked container, as returned by ListContainers().
///
/// Deliberately thin (no pod/labels/etc.) — callers that need full metadata do a
/// follow-up LookupByContainerId(). This keeps the enumeration response small when
/// the node is running hundreds of containers.
struct EXPORTED ContainerRef
{
    std::string runtime;       ///< "kubernetes" or "docker".
    std::string container_id;
    uint64_t    cgroup_id{0};  ///< 0 => not yet resolved.
};

/// @brief Synchronous Unix-domain-socket client for the container-connector IPC.
///
/// Designed for hot-path lookups from the syscheckd eBPF whodata pipeline:
/// short timeout (default 200 ms), single round-trip per call, connection is
/// opened and closed per request (no pool).
///
/// Failure modes (timeout, ECONNREFUSED, malformed response) are reported as
/// `found == false` with no exception, so the calling FIM pipeline can treat
/// "container connector unavailable" exactly like "not a tracked container":
/// the event flows through the host-FIM path instead.
class EXPORTED ContainerConnectorClient final
{
public:
    explicit ContainerConnectorClient(
        std::string                socket_path = "/var/ossec/queue/sockets/container_connector",
        std::chrono::milliseconds  timeout     = std::chrono::milliseconds(200));

    LookupResult LookupByCgroupId(uint64_t cgroup_id);
    LookupResult LookupByContainerId(const std::string& container_id);

    /// Enumerate every container currently tracked by the connector (both runtimes).
    /// Used by consumers that need to discover baseline targets rather than resolve
    /// one known identifier — e.g. "scan every already-running container at startup".
    /// Returns an empty vector on any failure (connector unavailable, malformed
    /// response); callers cannot distinguish "no containers" from "lookup failed"
    /// from the return value alone, same failure-degrades-to-empty policy as Lookup().
    std::vector<ContainerRef> ListContainers();

    /// Debug helper: returns the total number of containers cached, or -1 on error.
    long long Size();

private:
    LookupResult Lookup(const std::string& request_line);
    std::string  RoundTrip(const std::string& request_line);

    std::string               socket_path_;
    std::chrono::milliseconds timeout_;
};

} // namespace wazuh::container_connector

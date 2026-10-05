#pragma once

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "container_key_kind.h"
#include <chrono>
#include <cstdint>

#include <cstring>
#include <json.hpp>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wazuh::container_instances_client
{

    /// Outcome classes of an enrichment query (container_instances protocol v1).
    enum class LookupStatus : std::uint8_t
    {
        resolved,     ///< `json` holds the full enrichment record (the "data" object).
        pending,      ///< Cold cache: re-query later; never block on this.
        notContainer, ///< Permanent verdict: stop asking about this cgroup id.
        unavailable   ///< Module not running / socket missing / timeout / error.
    };

    struct LookupResult
    {
        LookupStatus status {LookupStatus::unavailable};

        /// The WHOLE reply line, for every status — not the "data" object and not
        /// the "reason" string. roundTrip() extracts only the outcome class and
        /// leaves parsing to the caller (see the note at the end of it), so a
        /// consumer wanting the enrichment record must parse this and descend
        /// into `data` itself. Empty when nothing was received.
        std::string json;
    };

    struct ContainerRef
    {
        std::string runtime;
        std::string containerId;
        std::uint64_t cgroupId {0};

        /// The container's FULL record as the `list` reply carried it — the same
        /// object a `resolve` would return in its "data" field (runtime, name,
        /// image, image_digest, restart_count, labels, network, oci_mounts, and
        /// the Kubernetes block when applicable).
        ///
        /// Keeping it means a consumer that needs the rich metadata for every
        /// container does NOT have to follow up with one `resolve` round-trip per
        /// container: `list` already sent all of it. Each round-trip is its own
        /// connect/send/recv/close against a 2-worker server with a 1 s timeout,
        /// so on a 100-container node this is the difference between 101
        /// connections and 1.
        nlohmann::json record;
    };

    /// One transition of the published container set.
    struct ContainerEventRef
    {
        enum class Kind
        {
            added,
            changed,
            removed
        };

        std::uint64_t seq {0};
        Kind kind {Kind::changed};
        std::string containerId;

        /// Last known cgroup inode, present on removals too — a consumer keyed
        /// on the inode cannot act on a removal it cannot map back to one.
        std::uint64_t cgroupId {0};

        /// Change classes as NAMES, verbatim from the wire. Deliberately not
        /// decoded into a bitmask here: a class this build does not know must
        /// stay visible so the consumer can treat it as "re-scan everything"
        /// rather than silently dropping it, which an unknown bit would do.
        std::vector<std::string> changed;

        /// Absent for removals.
        nlohmann::json record;
    };

    /// Reply to a cursor read. The three unhappy outcomes are deliberately
    /// distinct, because collapsing any two of them loses data:
    ///
    ///   available=false        nothing was obtained. NEVER sweep: this is
    ///                          indistinguishable from "no containers" only if
    ///                          the caller lets it be.
    ///   deltaSupported=false   the server predates cursors. Fall back to
    ///                          whole-list diffing; `containers` holds the set.
    ///   resyncRequired         the cursor could not be served. `containers`
    ///                          holds the full set, already fetched.
    struct ContainerDelta
    {
        bool available {false};
        bool deltaSupported {false};
        bool resyncRequired {false};

        std::uint64_t epoch {0};
        std::uint64_t seq {0};

        std::vector<ContainerEventRef> events;
        std::vector<ContainerRef> containers;
    };

    /// Synchronous, connect-per-request client for the Container Instances query
    /// socket. All failures collapse into `unavailable` (no exceptions) so callers
    /// fall back to the host code path.
    ///
    /// The default timeout is deliberately >= 1 s: a cold-cache resolution inside
    /// the module takes up to ~0.6 s before it answers `pending`.
    class ContainerInstancesClient final
    {
    public:
        explicit ContainerInstancesClient(std::string socketPath = "queue/sockets/container_instances",
                                          std::chrono::milliseconds timeout = std::chrono::milliseconds {1000})
            : m_socketPath(std::move(socketPath))
            , m_timeout(timeout)
        {
        }

        /// Resolve by whatever identifier this host uses.
        ///
        /// The KIND is sent, not assumed. On a host where the cgroup id is a
        /// constant the producer files containers under mount namespaces
        /// instead, and the two are both ordinary 64-bit inode numbers — asked
        /// for in the wrong space they do not error, they simply never match,
        /// and the caller is told the container is unknown.
        [[nodiscard]] LookupResult resolve(wz_container_key_kind_t kind, std::uint64_t key) const
        {
            return roundTrip(resolveRequest(kind, key, nullptr));
        }

        [[nodiscard]] LookupResult
        resolve(wz_container_key_kind_t kind, std::uint64_t key, const std::string& containerId) const
        {
            return roundTrip(resolveRequest(kind, key, &containerId));
        }

        /// Kept for callers that have not moved yet, and for hosts where the
        /// cgroup id IS the key. Equivalent to resolve(WZ_CONTAINER_KEY_CGROUP,
        /// ...), and refused by the producer on a host keyed otherwise — which
        /// is the correct answer, not a regression.
        [[nodiscard]] LookupResult resolveByCgroupId(std::uint64_t cgroupId) const
        {
            return resolve(WZ_CONTAINER_KEY_CGROUP, cgroupId);
        }

        [[nodiscard]] LookupResult resolveByCgroupId(std::uint64_t cgroupId, const std::string& containerId) const
        {
            return resolve(WZ_CONTAINER_KEY_CGROUP, cgroupId, containerId);
        }

        /// @brief List every container the connector currently knows about.
        ///
        /// @param reachable Optional. Set to true only when the connector
        ///        answered with a well-formed `status: ok` reply, false on any
        ///        transport or protocol failure. This matters because EVERY
        ///        failure mode below returns an empty vector, which is
        ///        otherwise indistinguishable from a node that genuinely runs
        ///        no containers — and callers that derive deletions from this
        ///        list would then delete every stored row the moment the
        ///        connector blips. Callers that only iterate what they got can
        ///        keep ignoring it.
        [[nodiscard]] std::vector<ContainerRef> listContainers(bool* reachable = nullptr) const
        {
            std::vector<ContainerRef> result;

            if (reachable != nullptr)
            {
                *reachable = false;
            }

            const auto reply = roundTrip(R"({"version":2,"op":"list"})");
            if (reply.json.empty())
            {
                return result;
            }

            const auto parsed = nlohmann::json::parse(reply.json, nullptr, false);
            if (parsed.is_discarded() || !parsed.is_object() || parsed.value("status", "") != "ok")
            {
                return result;
            }

            const auto containersIt = parsed.find("containers");
            if (containersIt == parsed.end() || !containersIt->is_array())
            {
                return result;
            }

            // From here the reply is a well-formed `ok` list: an empty array now
            // means "no containers", which is authoritative.
            if (reachable != nullptr)
            {
                *reachable = true;
            }

            for (const auto& item : *containersIt)
            {
                auto ref = parseContainerRef(item);
                if (ref)
                {
                    result.push_back(std::move(*ref));
                }
            }

            return result;
        }

        /// @brief Read forward from `from`, instead of fetching the whole set.
        ///
        /// Rides the same `list` op with two extra fields, so a server that
        /// predates cursors answers normally and simply omits the epoch —
        /// which is how `deltaSupported` is detected. There is no error path
        /// for talking to an old server, by design.
        ///
        /// Pass a default-constructed cursor to start following from cold; that
        /// reports `resyncRequired` with the full set attached, which is the
        /// same shape as recovering from a gap and so needs no separate
        /// handling in the caller.
        [[nodiscard]] ContainerDelta listContainersSince(std::uint64_t epoch, std::uint64_t seq) const
        {
            ContainerDelta delta;

            const auto request = std::string {R"({"version":2,"op":"list","since_epoch":")"} + std::to_string(epoch) +
                                 R"(","since_seq":")" + std::to_string(seq) + R"("})";

            const auto reply = roundTrip(request);
            if (reply.json.empty())
            {
                return delta; // available stays false: do not sweep.
            }

            const auto parsed = nlohmann::json::parse(reply.json, nullptr, false);
            if (parsed.is_discarded() || !parsed.is_object() || parsed.value("status", "") != "ok")
            {
                return delta;
            }

            const auto containersIt = parsed.find("containers");
            if (containersIt == parsed.end() || !containersIt->is_array())
            {
                return delta;
            }

            // A well-formed `ok` list reply: whatever else is true, the
            // connector answered and its view is authoritative.
            delta.available = true;

            for (const auto& item : *containersIt)
            {
                auto ref = parseContainerRef(item);
                if (ref)
                {
                    delta.containers.push_back(std::move(*ref));
                }
            }

            const auto epochIt = parsed.find("epoch");
            if (epochIt == parsed.end() || !epochIt->is_string())
            {
                // An older server. It answered with the full set, which the
                // caller diffs as it always did.
                return delta;
            }

            delta.deltaSupported = true;
            delta.epoch = parseDecimalU64(*epochIt);
            delta.seq = parseDecimalU64(parsed.value("seq", std::string {"0"}));
            delta.resyncRequired = parsed.value("resync_required", false);

            if (delta.resyncRequired)
            {
                // containers already holds the full set; events are meaningless.
                return delta;
            }

            const auto eventsIt = parsed.find("events");
            if (eventsIt == parsed.end() || !eventsIt->is_array())
            {
                return delta; // supported, nothing changed.
            }

            for (const auto& item : *eventsIt)
            {
                if (!item.is_object())
                {
                    continue;
                }

                ContainerEventRef event;
                event.seq = parseDecimalU64(item.value("seq", std::string {"0"}));
                event.containerId = item.value("container_id", std::string {});
                // `key` first, `cgroup_id` as the fallback for a producer that
                // predates v2. Note the producer OMITS cgroup_id where it would
                // not be one, so this never reads a namespace inode as a cgroup.
                event.cgroupId = parseDecimalU64(item.value("key", item.value("cgroup_id", std::string {"0"})));

                if (event.containerId.empty())
                {
                    continue;
                }

                const auto kind = item.value("kind", std::string {});
                if (kind == "added")
                {
                    event.kind = ContainerEventRef::Kind::added;
                }
                else if (kind == "removed")
                {
                    event.kind = ContainerEventRef::Kind::removed;
                }
                else if (kind == "changed")
                {
                    event.kind = ContainerEventRef::Kind::changed;
                }
                else
                {
                    // A kind this build does not know. Skipping it would drop a
                    // transition silently and leave the caller's view wrong
                    // with no way to notice; a resync is the conservative read.
                    delta.resyncRequired = true;
                    delta.events.clear();
                    return delta;
                }

                if (const auto it = item.find("changed"); it != item.end() && it->is_array())
                {
                    for (const auto& name : *it)
                    {
                        if (name.is_string())
                        {
                            event.changed.push_back(name.get<std::string>());
                        }
                    }
                }
                if (const auto it = item.find("data"); it != item.end())
                {
                    event.record = *it;
                }

                delta.events.push_back(std::move(event));
            }

            return delta;
        }

        [[nodiscard]] std::string status() const
        {
            return roundTrip(R"({"version":2,"op":"status"})").json;
        }

    private:
        /// Builds a v2 resolve line. Kept in one place so the key and its kind
        /// cannot be sent apart — a key with no kind is refused by the
        /// producer, which is correct but would be a pointless round trip.
        [[nodiscard]] static std::string
        resolveRequest(wz_container_key_kind_t kind, std::uint64_t key, const std::string* containerId)
        {
            std::string line = R"({"version":2,"op":"resolve","key_kind":")";
            line += wz_container_key_kind_name(kind);
            line += R"(","key":")";
            line += std::to_string(key);
            line += R"(")";
            if (containerId != nullptr)
            {
                line += R"(,"container_id":")" + *containerId + R"(")";
            }
            line += "}";
            return line;
        }

        [[nodiscard]] LookupResult roundTrip(const std::string& request) const
        {
            LookupResult result;

            const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0)
            {
                return result;
            }

            timeval timeout {};
            timeout.tv_sec = static_cast<time_t>(m_timeout.count() / 1000);
            timeout.tv_usec = static_cast<suseconds_t>((m_timeout.count() % 1000) * 1000);
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            sockaddr_un address {};
            address.sun_family = AF_UNIX;
            if (m_socketPath.size() >= sizeof(address.sun_path))
            {
                ::close(fd);
                return result;
            }
            std::strncpy(address.sun_path, m_socketPath.c_str(), sizeof(address.sun_path) - 1);

            const std::string line = request + "\n";
            std::string reply;
            if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0 &&
                ::send(fd, line.data(), line.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(line.size()))
            {
                char buffer[65536];
                while (reply.find('\n') == std::string::npos)
                {
                    const auto received = ::recv(fd, buffer, sizeof(buffer), 0);
                    if (received <= 0)
                    {
                        break;
                    }
                    reply.append(buffer, static_cast<std::size_t>(received));
                }
            }
            ::close(fd);

            if (const auto newline = reply.find('\n'); newline != std::string::npos)
            {
                reply.resize(newline);
            }
            if (reply.empty())
            {
                return result;
            }

            // Cheap status extraction: consumers parse the full JSON themselves if
            // they need more than the outcome class.
            result.json = reply;
            if (reply.find(R"("status":"resolved")") != std::string::npos)
            {
                result.status = LookupStatus::resolved;
            }
            else if (reply.find(R"("status":"pending")") != std::string::npos)
            {
                result.status = LookupStatus::pending;
            }
            else if (reply.find(R"("status":"not_container")") != std::string::npos)
            {
                result.status = LookupStatus::notContainer;
            }
            return result;
        }

        /// One container record from a `list` reply or an event's `data`.
        /// nullopt when it carries no container id, which is the only field
        /// without which nothing downstream can use it.
        [[nodiscard]] static std::optional<ContainerRef> parseContainerRef(const nlohmann::json& item)
        {
            if (!item.is_object())
            {
                return std::nullopt;
            }

            ContainerRef ref;
            if (const auto it = item.find("runtime"); it != item.end() && it->is_string())
            {
                ref.runtime = it->get<std::string>();
            }
            if (const auto it = item.find("container_id"); it != item.end() && it->is_string())
            {
                ref.containerId = it->get<std::string>();
            }
            if (auto it = item.find("key"); it != item.end() && it->is_string())
            {
                ref.cgroupId = parseDecimalU64(*it);
            }
            else if (it = item.find("cgroup_id"); it != item.end() && it->is_string())
            {
                ref.cgroupId = parseDecimalU64(*it);
            }
            if (ref.containerId.empty())
            {
                return std::nullopt;
            }
            ref.record = item;
            return ref;
        }

        /// 64-bit values travel as decimal strings on this protocol: cJSON
        /// parses JSON numbers as doubles and silently rounds above 2^53.
        /// Anything unparseable reads as 0, which every caller already treats
        /// as "not known".
        [[nodiscard]] static std::uint64_t parseDecimalU64(const nlohmann::json& value)
        {
            if (!value.is_string())
            {
                return 0;
            }
            try
            {
                return std::stoull(value.get<std::string>());
            }
            catch (...)
            {
                return 0;
            }
        }

        [[nodiscard]] static std::uint64_t parseDecimalU64(const std::string& value)
        {
            try
            {
                return std::stoull(value);
            }
            catch (...)
            {
                return 0;
            }
        }

        std::string m_socketPath;
        std::chrono::milliseconds m_timeout;
    };

} // namespace wazuh::container_instances_client

#pragma once

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <json.hpp>
#include <cstring>
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
        std::string json; ///< resolved: the "data" object; notContainer: the "reason" string.
    };

    struct ContainerRef
    {
        std::string runtime;
        std::string containerId;
        std::uint64_t cgroupId {0};
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

        [[nodiscard]] LookupResult resolveByCgroupId(std::uint64_t cgroupId) const
        {
            return roundTrip(R"({"version":1,"op":"resolve","cgroup_id":")" + std::to_string(cgroupId) + R"("})");
        }

        [[nodiscard]] LookupResult resolveByCgroupId(std::uint64_t cgroupId, const std::string& containerId) const
        {
            return roundTrip(R"({"version":1,"op":"resolve","cgroup_id":")" + std::to_string(cgroupId) +
                             R"(","container_id":")" + containerId + R"("})");
        }

        [[nodiscard]] std::vector<ContainerRef> listContainers() const
        {
            std::vector<ContainerRef> result;
            const auto reply = roundTrip(R"({"version":1,"op":"list"})");
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

            for (const auto& item : *containersIt)
            {
                if (!item.is_object())
                {
                    continue;
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
                if (const auto it = item.find("cgroup_id"); it != item.end() && it->is_string())
                {
                    try
                    {
                        ref.cgroupId = std::stoull(it->get<std::string>());
                    }
                    catch (...)
                    {
                        ref.cgroupId = 0;
                    }
                }
                if (ref.containerId.empty())
                {
                    continue;
                }
                result.push_back(std::move(ref));
            }

            return result;
        }

        [[nodiscard]] std::string status() const
        {
            return roundTrip(R"({"version":1,"op":"status"})").json;
        }

    private:
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

        std::string m_socketPath;
        std::chrono::milliseconds m_timeout;
    };

} // namespace wazuh::container_instances_client

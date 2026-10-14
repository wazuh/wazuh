#include "lifecycle_notifier.hpp"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>

namespace wazuh::container_instances
{

    LifecycleNotifier::LifecycleNotifier(std::vector<std::string> socketPaths, Logger logger)
        : m_logger(std::move(logger))
    {
        m_targets.reserve(socketPaths.size());
        for (auto& path : socketPaths)
        {
            if (!path.empty())
            {
                m_targets.push_back(Target {std::move(path), true});
            }
        }

        if (m_targets.empty())
        {
            return;
        }

        // Unbound and non-blocking: this socket only ever sends. SOCK_DGRAM so a
        // consumer that is not reading cannot apply back-pressure to the
        // reconcile that is calling us.
        m_fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

        if (m_fd < 0)
        {
            m_logger(LogLevel::warn,
                     std::string {"Could not create the lifecycle notification socket: "} + std::strerror(errno) +
                         ". Consumers will fall back to their own polling.");
        }
    }

    LifecycleNotifier::~LifecycleNotifier()
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
        }
    }

    void LifecycleNotifier::notify(const LifecycleCursor& cursor)
    {
        if (m_fd < 0)
        {
            return;
        }

        // Decimal strings, not JSON numbers: both values are 64-bit and every
        // consumer of this protocol family parses numbers as doubles, which
        // silently rounds above 2^53.
        const std::string payload = "{\"epoch\":\"" + std::to_string(cursor.epoch) + "\",\"seq\":\"" +
                                    std::to_string(cursor.seq) + "\"}";

        for (auto& target : m_targets)
        {
            sockaddr_un address {};
            address.sun_family = AF_UNIX;

            if (target.path.size() >= sizeof(address.sun_path))
            {
                if (target.lastSendOk)
                {
                    target.lastSendOk = false;
                    m_logger(LogLevel::warn,
                             "Lifecycle notification path is too long for a unix socket: " + target.path);
                }
                continue;
            }
            std::memcpy(address.sun_path, target.path.c_str(), target.path.size());

            const auto sent = ::sendto(m_fd,
                                       payload.data(),
                                       payload.size(),
                                       MSG_DONTWAIT,
                                       reinterpret_cast<const sockaddr*>(&address),
                                       sizeof(address));

            const bool ok = sent >= 0;

            // Logged only when the answer changes. ENOENT is the ordinary case —
            // that consumer is not running, or has the feature off — and this
            // runs on every reconcile, so reporting each one would turn a
            // non-event into a log flood.
            if (ok != target.lastSendOk)
            {
                target.lastSendOk = ok;

                if (ok)
                {
                    m_logger(LogLevel::debug, "Lifecycle notifications reaching " + target.path + " again");
                }
                else
                {
                    m_logger(LogLevel::debug,
                             "Lifecycle notifications to " + target.path + " are not being delivered (" +
                                 std::strerror(errno) + "); that consumer keeps polling instead");
                }
            }
        }
    }

} // namespace wazuh::container_instances

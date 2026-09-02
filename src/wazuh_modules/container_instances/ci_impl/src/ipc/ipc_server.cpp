#include "ipc_server.hpp"

#include "wire_protocol.hpp"

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        constexpr std::size_t MAX_REQUEST_BYTES = 8192;
        constexpr int CLIENT_READ_TIMEOUT_MS = 5000;

        void closeIfOpen(int& fd)
        {
            if (fd >= 0)
            {
                ::close(fd);
                fd = -1;
            }
        }

    } // namespace

    IpcServer::IpcServer(IQueryHandler& handler, std::string socketPath, Logger logger, std::size_t workerCount)
        : m_handler(handler)
        , m_socketPath(std::move(socketPath))
        , m_logger(std::move(logger))
        , m_workerCount(workerCount)
    {
    }

    IpcServer::~IpcServer()
    {
        stop();
    }

    void IpcServer::start()
    {
        sockaddr_un address {};
        address.sun_family = AF_UNIX;
        if (m_socketPath.size() >= sizeof(address.sun_path))
        {
            throw std::runtime_error("IPC socket path too long: " + m_socketPath);
        }
        std::strncpy(address.sun_path, m_socketPath.c_str(), sizeof(address.sun_path) - 1);

        m_listenFd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (m_listenFd < 0)
        {
            throw std::runtime_error("IPC socket creation failed: " + std::string {std::strerror(errno)});
        }

        ::unlink(m_socketPath.c_str()); // Stale socket from a previous run.
        if (::bind(m_listenFd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(m_listenFd, SOMAXCONN) != 0)
        {
            const std::string reason {std::strerror(errno)};
            closeIfOpen(m_listenFd);
            throw std::runtime_error("IPC socket bind/listen on " + m_socketPath + " failed: " + reason);
        }
        ::chmod(m_socketPath.c_str(), 0660);

        m_wakeupFd = ::eventfd(0, EFD_CLOEXEC);
        if (m_wakeupFd < 0)
        {
            closeIfOpen(m_listenFd);
            throw std::runtime_error("IPC eventfd creation failed: " + std::string {std::strerror(errno)});
        }

        m_stopping.store(false);
        for (std::size_t i = 0; i < m_workerCount; ++i)
        {
            m_workers.emplace_back([this] { workerLoop(); });
        }
        m_acceptThread = std::thread([this] { acceptLoop(); });

        m_logger(LogLevel::info, "Enrichment query socket listening at " + m_socketPath);
    }

    void IpcServer::stop()
    {
        if (m_stopping.exchange(true))
        {
            // Idempotent, but threads may still need joining from a partial stop.
        }

        if (m_wakeupFd >= 0)
        {
            const std::uint64_t one = 1;
            const auto written = ::write(m_wakeupFd, &one, sizeof(one));
            static_cast<void>(written);
        }
        m_queueCv.notify_all();

        if (m_acceptThread.joinable())
        {
            m_acceptThread.join();
        }
        for (auto& worker : m_workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
        m_workers.clear();

        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            for (const int fd : m_pendingClients)
            {
                ::close(fd);
            }
            m_pendingClients.clear();
        }

        closeIfOpen(m_listenFd);
        closeIfOpen(m_wakeupFd);
        if (!m_socketPath.empty())
        {
            ::unlink(m_socketPath.c_str());
        }
    }

    void IpcServer::acceptLoop()
    {
        while (!m_stopping.load())
        {
            pollfd fds[2] {};
            fds[0].fd = m_listenFd;
            fds[0].events = POLLIN;
            fds[1].fd = m_wakeupFd;
            fds[1].events = POLLIN;

            if (::poll(fds, 2, -1) < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                m_logger(LogLevel::warn, std::string {"IPC accept poll failed: "} + std::strerror(errno));
                return;
            }
            if ((fds[1].revents & POLLIN) != 0 || m_stopping.load())
            {
                return;
            }
            if ((fds[0].revents & POLLIN) == 0)
            {
                continue;
            }

            const int clientFd = ::accept4(m_listenFd, nullptr, nullptr, SOCK_CLOEXEC);
            if (clientFd < 0)
            {
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_pendingClients.push_back(clientFd);
            }
            m_queueCv.notify_one();
        }
    }

    void IpcServer::workerLoop()
    {
        while (true)
        {
            int clientFd = -1;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_queueCv.wait(lock, [this] { return m_stopping.load() || !m_pendingClients.empty(); });
                if (m_stopping.load())
                {
                    return;
                }
                clientFd = m_pendingClients.front();
                m_pendingClients.pop_front();
            }
            handleClient(clientFd);
        }
    }

    void IpcServer::handleClient(int clientFd)
    {
        std::string requestLine;
        bool complete = false;

        while (requestLine.size() < MAX_REQUEST_BYTES && !m_stopping.load())
        {
            pollfd fd {};
            fd.fd = clientFd;
            fd.events = POLLIN;
            const int ready = ::poll(&fd, 1, CLIENT_READ_TIMEOUT_MS);
            if (ready <= 0)
            {
                break; // Timeout or error: drop the client.
            }

            char buffer[1024];
            const auto received = ::recv(clientFd, buffer, sizeof(buffer), 0);
            if (received <= 0)
            {
                break;
            }
            requestLine.append(buffer, static_cast<std::size_t>(received));
            if (const auto newline = requestLine.find('\n'); newline != std::string::npos)
            {
                requestLine.resize(newline);
                complete = true;
                break;
            }
        }

        if (complete)
        {
            auto parsed = wire::parseRequest(requestLine);
            const auto response = std::holds_alternative<QueryRequest>(parsed)
                                      ? m_handler.handle(std::get<QueryRequest>(parsed))
                                      : std::get<QueryResponse>(parsed);
            const auto wireResponse = wire::serializeResponse(response) + "\n";
            static_cast<void>(::send(clientFd, wireResponse.data(), wireResponse.size(), MSG_NOSIGNAL));
        }

        ::close(clientFd);
    }

} // namespace wazuh::container_instances

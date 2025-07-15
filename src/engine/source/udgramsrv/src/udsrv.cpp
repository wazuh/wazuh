#include <udgramsrv/udsrv.hpp>

#include <cstdio>
#include <cstring>
#include <stdexcept>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <fmt/format.h>

#include <base/logging.hpp>

namespace udsrv
{

Server::Server(std::function<void(std::string_view)> handler, std::string socketPath)
    : m_handler(std::move(handler))
    , m_socketPath(std::move(socketPath))
    , m_sockFd(-1)
    , m_running(false)
{
    // Remove any existing socket file at m_socketPath
    ::unlink(m_socketPath.c_str());

    // Create an AF_UNIX datagram socket
    m_sockFd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (m_sockFd < 0)
    {
        int err = errno;
        throw std::runtime_error(fmt::format("Event Server: socket() failed ({}): {}", err, std::strerror(err)));
    }

    // Prepare sockaddr_un
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (m_socketPath.size() >= sizeof(addr.sun_path))
    {
        ::close(m_sockFd);
        throw std::runtime_error(fmt::format("Event Server: socket path '{}' is too long ({} chars, max {})",
                                             m_socketPath,
                                             m_socketPath.size(),
                                             sizeof(addr.sun_path) - 1));
    }
    std::strncpy(addr.sun_path, m_socketPath.c_str(), sizeof(addr.sun_path) - 1);

    // Set timeout for recv() to 100 ms for checking if the server is still running
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 100 ms
    if (setsockopt(m_sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        int err = errno;
        ::close(m_sockFd);
        throw std::runtime_error(
            fmt::format("Event Server: setsockopt(SO_RCVTIMEO) failed ({}): {}", err, std::strerror(err)));
    }

    // Bind the socket to the path
    size_t addrlen = offsetof(sockaddr_un, sun_path) + m_socketPath.size();
    if (::bind(m_sockFd, reinterpret_cast<const sockaddr*>(&addr), static_cast<socklen_t>(addrlen)) < 0)
    {
        int err = errno;
        ::unlink(m_socketPath.c_str());
        ::close(m_sockFd);
        throw std::runtime_error("Event Server: bind() failed: " + std::string(std::strerror(err)));
    }

    // Set file mode to 0660 (owner and group can read/write)
    if (::chmod(m_socketPath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0)
    {
        int err = errno;
        ::close(m_sockFd);
        ::unlink(m_socketPath.c_str());
        throw std::runtime_error(fmt::format("Event Server: chmod() failed ({}): {}", err, std::strerror(err)));
    }
}

void Server::start(size_t poolSize)
{
    if (m_running.load())
    {
        throw std::runtime_error("Event Server: start() called when already running");
    }
    if (poolSize == 0)
    {
        throw std::runtime_error("Event Server: start() called with poolSize == 0");
    }

    m_running.store(true);
    m_threads.reserve(poolSize);
    for (size_t i = 0; i < poolSize; ++i)
    {
        m_threads.emplace_back(&Server::workerLoop, this);
    }
}

void Server::stop()
{
    if (!m_running.exchange(false))
    {
        // Already stopped, nothing to do
        return;
    }

    if (m_sockFd >= 0)
    {
        ::close(m_sockFd);
        m_sockFd = -1;
    }

    for (auto& t : m_threads)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
    m_threads.clear();
}

Server::~Server()
{
    stop();
    ::unlink(m_socketPath.c_str());
}

void Server::workerLoop()
{
    // Each worker allocates a buffer of size 65536 bytes (max size of a datagram)
    constexpr size_t MAX_DATAGRAM = (0x1 << 16);
    std::vector<char> buffer;
    buffer.reserve(MAX_DATAGRAM);

    while (m_running.load())
    {
        buffer.clear();
        ssize_t n = ::recv(m_sockFd, buffer.data(), buffer.capacity(), 0); // Block on recv() with a timeout
        if (n <= 0)
        {
            // Ignore signals unless we are not running
            if (!m_running.load())
            {
                break;
            }
            continue;
        }

        try
        {
            m_handler(std::string_view(buffer.data(), static_cast<size_t>(n)));
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L(
                "Server event", "Error handling event: {}. Message: {}", e.what(), std::string(buffer.data(), n));
        }
    }
}

} // namespace udsrv

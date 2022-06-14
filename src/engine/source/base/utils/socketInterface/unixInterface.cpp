#include "unixInterface.hpp"

#include <iostream>
#include <unistd.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <logging/logging.hpp>

namespace base::utils::socketInterface
{

// Private
bool unixInterface::setSocketSize() const noexcept
{

    auto retval {false};
    const std::vector<int> optNames {SO_RCVBUF, SO_SNDBUF};

    for (const auto optName : optNames)
    {
        int len;
        socklen_t optlen {sizeof(len)};
        /* Get current maximum size */
        if (getsockopt(m_sock, SOL_SOCKET, optName, (void*)&len, &optlen) == -1)
        {
            len = 0;
        }

        /* Set maximum message size only if it is bigger than the current value */
        if (m_maxMsgSize > len)
        {
            len = m_maxMsgSize;
            if (setsockopt(m_sock, SOL_SOCKET, optName, (const void*)&len, optlen) == -1)
            {
                retval = true;
                break;
            }
        }
    }

    return retval;
}

// Protect
unixInterface::unixInterface(std::string_view path,
                             const Protocol protocol,
                             const int maxMsgSize)
    : m_path(path)
    , m_protocol(protocol)
    , m_maxMsgSize(maxMsgSize)
{
    if (m_path.empty())
    {
        throw std::invalid_argument("unixInterface: path is empty");
    }
}
// Public
unixInterface::~unixInterface()
{
    socketDisconnect();
}

void unixInterface::socketDisconnect()
{
    if (0 < m_sock)
    {
        WAZUH_LOG_DEBUG("Closing {}...", m_path);
        close(m_sock);
        m_sock = -1;
    }
}

bool unixInterface::isConnected() const noexcept
{
    return (0 < m_sock);
}

void unixInterface::socketConnect()
{
    /* Check reconexion */
    if (0 < m_sock)
    {
        WAZUH_LOG_DEBUG("Already open socket '{}', closing before reconnecting...",
                        m_path);
        close(m_sock);
        m_sock = -1;
    }
    WAZUH_LOG_DEBUG("Connecting to '{}'...", m_path);

    /* Config the socket address */
    struct sockaddr_un sAddr
    {
        .sun_family = AF_UNIX, .sun_path = {}
    };
    strncpy(sAddr.sun_path, m_path.data(), sizeof(sAddr.sun_path) - 1);

    /* Create the socket */
    const auto socketType = (m_protocol == Protocol::STREAM) ? SOCK_STREAM : SOCK_DGRAM;
    m_sock = socket(PF_UNIX, socketType, 0);
    if (0 > m_sock)
    {

        const auto msg = fmt::format(
            "Cannot create the socket '{}': {} ({})", m_path, strerror(errno), errno);

        throw std::runtime_error(msg);
    }

    /* Connect to the UNIX domain */
    if (connect(m_sock, reinterpret_cast<struct sockaddr*>(&sAddr), SUN_LEN(&sAddr)) < 0)
    {
        close(m_sock);
        const auto msg = fmt::format(
            "Cannot connect to '{}': {} ({})", m_path, strerror(errno), errno);

        throw std::runtime_error(msg);
    }

    /* Set socket buffer maximum size */
    if (setSocketSize())
    {
        close(m_sock);
        m_sock = -1;
        const auto msg = fmt::format("Cannot set socket buffer size to '{}': {} ({})",
                                     m_path,
                                     strerror(errno),
                                     errno);

        throw std::runtime_error(msg);
    }

    if (fcntl(m_sock, F_SETFD, FD_CLOEXEC) == -1)
    {
        WAZUH_LOG_WARN(
            "Cannot set close-on-exec flag to socket: {} ({})", strerror(errno), errno);
    }
}

} // namespace base::utils::socketInterface

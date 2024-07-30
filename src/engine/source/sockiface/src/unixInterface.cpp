#include "unixInterface.hpp"

#include <iostream>
#include <unistd.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <base/logging.hpp>

namespace sockiface
{

// Private
bool unixInterface::setSocketSize() const noexcept
{

    auto retval {false};
    const std::vector<int> optNames {SO_RCVBUF, SO_SNDBUF};

    for (const auto optName : optNames)
    {
        uint32_t len;
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
unixInterface::unixInterface(std::string_view path, const Protocol protocol, const uint32_t maxMsgSize)
    : m_path(path)
    , m_protocol(protocol)
    , m_maxMsgSize(maxMsgSize)
{
    if (m_path.empty())
    {
        throw std::invalid_argument("Engine Unix interface utils: Socket path is empty");
    }
    if (0 == m_maxMsgSize)
    {
        throw std::invalid_argument("Engine Unix interface utils: Parameter 'maxMsgSize' cannot be set to zero");
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
        LOG_DEBUG("Engine Unix interface utils: Closing '{}'...", m_path);
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
        LOG_DEBUG("Engine Unix interface utils: Socket '{}' is already opened, closing it before reconnecting...",
                  m_path);
        close(m_sock);
        m_sock = -1;
    }

    LOG_DEBUG("Engine Unix interface utils: Connecting to '{}'...", m_path);

    /* Config the socket address */
    struct sockaddr_un sAddr
    {
        .sun_family = AF_UNIX, .sun_path = {}
    };
    strncpy(sAddr.sun_path, m_path.data(), sizeof(sAddr.sun_path) - 1);

    /* Create the socket */
    const auto socketType {(Protocol::STREAM == m_protocol) ? SOCK_STREAM : SOCK_DGRAM};
    m_sock = socket(PF_UNIX, socketType, 0);
    if (0 > m_sock)
    {
        throw std::runtime_error(fmt::format(
            "Engine Unix interface utils: Cannot create the socket '{}': {} ({})", m_path, strerror(errno), errno));
    }

    /* Connect to the UNIX domain */
    if (connect(m_sock, reinterpret_cast<struct sockaddr*>(&sAddr), SUN_LEN(&sAddr)) < 0)
    {
        close(m_sock);
        throw std::runtime_error(fmt::format(
            "Engine Unix interface utils: Cannot connect to '{}': {} ({})", m_path, strerror(errno), errno));
    }

    /* Set socket buffer maximum size */
    if (setSocketSize())
    {
        close(m_sock);
        m_sock = -1;

        throw std::runtime_error(
            fmt::format("Engine Unix interface utils: Cannot set socket buffer size to '{}': {} ({})",
                        m_path,
                        strerror(errno),
                        errno));
    }

    if (fcntl(m_sock, F_SETFD, FD_CLOEXEC) == -1)
    {
        LOG_WARNING("Engine Unix interface utils: Cannot set the 'close-on-exec' flag on the socket '{}': {} ({}).",
                    m_path,
                    strerror(errno),
                    errno);
    }

    LOG_DEBUG("Engine Unix interface utils: Connected to '{}'.", m_path);
}

} // namespace sockiface

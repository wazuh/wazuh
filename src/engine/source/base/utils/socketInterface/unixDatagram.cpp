#include "unixDatagram.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdexcept>
#include <unistd.h>

#include <logging/logging.hpp>

namespace base::utils::socketInterface::unixDatagram
{

int socketConnect(std::string_view path) {

    if (path.empty())
    {
        throw std::runtime_error("socketConnect: path is empty");
    }

    /* Config the socket address */
    struct sockaddr_un sAddr
    {
        .sun_family = AF_UNIX, .sun_path = {}
    };
    strncpy(sAddr.sun_path, path.data(), sizeof(sAddr.sun_path) - 1);

    /* Get the socket fd connector */
    const auto socketFD {socket(PF_UNIX, SOCK_DGRAM, 0)};
    if (0 > socketFD)
    {
        const auto msg = std::string {"Cannot create the socket: "} + strerror(errno)
                         + " (" + std::to_string(errno) + ")";

        throw std::runtime_error(msg);
    }

    /* Connect to the UNIX domain */
    if (connect(socketFD, reinterpret_cast<struct sockaddr*>(&sAddr), SUN_LEN(&sAddr))
        < 0)
    {
        close(socketFD);
        const auto msg = std::string {"Cannot connect: "} + strerror(errno) + " ("
                         + std::to_string(errno) + ")";
        throw std::runtime_error(msg);
    }

    /* Set socket buffer maximum size */
    // TODO: check if this is really needed
    {
        int len;
        socklen_t optlen {sizeof(len)};
        /* Get current maximum size only send sock */
        if (getsockopt(socketFD, SOL_SOCKET, SO_SNDBUF, (void*)&len, &optlen) == -1)
        {
            len = 0;
        }

        /* Set maximum message size only recve sock */
        if (MSG_MAX_SIZE > len)
        {
            len = MSG_MAX_SIZE;
            if (setsockopt(socketFD, SOL_SOCKET, SO_SNDBUF, (const void*)&len, optlen)
                == -1)
            {
                close(socketFD);
                const auto msg = std::string {"Cannot set socket buffer size: "}
                                 + strerror(errno) + " (" + std::to_string(errno) + ")";
                throw std::runtime_error(msg);
            }
        }
    }

    // Set close-on-exec
    if (fcntl(socketFD, F_SETFD, FD_CLOEXEC) == -1)
    {
        WAZUH_LOG_WARN(
            "Cannot set close-on-exec flag to socket: {} ({})", strerror(errno), errno);
    }

    return socketFD;
}

CommRetval sendMsg(const int sock, const std::string& msg) {

    auto result {CommRetval::SOCKET_ERROR};
    auto payloadSize {msg.size()};

    // Validate
    if (0 >= sock)
    {
        result = CommRetval::INVALID_SOCKET;
    }
    else if (0 >= payloadSize)
    {
        result = CommRetval::SIZE_ZERO;
    }
    else if (MSG_MAX_SIZE < payloadSize)
    {
        result = CommRetval::SIZE_TOO_LONG;
    }
    else
    {
        // Send the message
        const auto sent {send(sock, msg.data(), payloadSize, MSG_NOSIGNAL)};
        if (sent < 0)
        {
            result = CommRetval::SOCKET_ERROR;
        }
        else if (sent != payloadSize)
        {
            result = CommRetval::SOCKET_ERROR;
        }
        else
        {
            result = CommRetval::SUCCESS;
        }
    }

    return result;
}
}

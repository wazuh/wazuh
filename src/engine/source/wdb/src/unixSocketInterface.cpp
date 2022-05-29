
#include "unixSocketInterface.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <logging/logging.hpp>

namespace socketinterface
{

// Namespace of private functions
namespace
{

/**
 * @brief Receive a message from a stream socket, full message (MSG_WAITALL)
 *
 * @param sock sock file descriptor.
 * @param buf buffer to store the message.
 * @param size size of the buffer.
 * @return int size of the message on success.
 * @return 0 on socket disconnected or timeout.
 * @return \ref SOCKET_ERROR otherwise (and errno is set).
 *
 * @warning This function blocks until the message is received or the socket is
 * disconnected.
 *
 */
ssize_t recvWaitAll(int sock, void* buf, size_t size) noexcept
{
    ssize_t offset {}; // offset in the buffer
    ssize_t recvb {};  // Recived bytes

    for (offset = 0; offset < size; offset += recvb)
    {
        recvb = recv(sock, (char*)buf + offset, size - offset, 0);

        if (0 >= recvb)
        {
            offset = recvb;
            break;
        }
    }

    return offset;
}
} // namespace

int socketConnect(std::string_view path)
{

    if (path.empty())
    {
        throw std::runtime_error("socketConnect: path is empty");
    }

    /* Socket options */
    const auto SOCK_TYPE {SOCK_STREAM};

    /* Config the socket address */
    struct sockaddr_un sAddr
    {
        .sun_family = AF_UNIX, .sun_path = {}
    };
    strncpy(sAddr.sun_path, path.data(), sizeof(sAddr.sun_path) - 1);

    /* Get the socket fd connector */
    const auto socketFD {socket(PF_UNIX, SOCK_TYPE, 0)};
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
    {
        int len;
        socklen_t optlen {sizeof(len)};
        /* Get current maximum size only recve sock */
        if (getsockopt(socketFD, SOL_SOCKET, SO_RCVBUF, (void*)&len, &optlen) == -1)
        {
            len = 0;
        }

        /* Set maximum message size only recve sock */
        if (MSG_MAX_SIZE > len)
        {
            len = MSG_MAX_SIZE;
            if (setsockopt(socketFD, SOL_SOCKET, SO_RCVBUF, (const void*)&len, optlen)
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

    return (socketFD);
}

CommRetval sendMsg(const int sock, const std::string& msg)
{

    auto result {CommRetval::SOCKET_ERROR};
    auto payloadSize {static_cast<uint32_t>(msg.size())};
    const auto HEADER_SIZE {sizeof(uint32_t)};

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
        payloadSize++; // send the null terminator
        // MSG_NOSIGNAL prevent broken pipe signal
        auto success {send(sock, &payloadSize, HEADER_SIZE, MSG_NOSIGNAL) == HEADER_SIZE};
        success = success
                  && (send(sock, msg.c_str(), payloadSize, MSG_NOSIGNAL) == payloadSize);

        if (success)
        {
            result = CommRetval::SUCCESS;
        }
        else if (EAGAIN == errno || EWOULDBLOCK == errno)
        {
            WAZUH_LOG_WARN("wdb socket is full: {} ({})", strerror(errno), errno);
        }
        else if (EPIPE == errno)
        {
            // Recoverable case
            throw RecoverableError("sendMsg socket is disconnected.");
        }
    }

    return result;
}

std::vector<char> recvMsg(const int sock)
{
    // Check recive msg
    const auto checkRcv = [](const ssize_t rcvBytes)
    {
        if (rcvBytes < 0)
        {
            const auto msg = std::string {"recvMsg: recv error : "} + strerror(errno)
                             + " (" + std::to_string(errno) + ")";
            if (ECONNRESET == errno)
            {
                // recoverable case
                throw RecoverableError(msg);
            }
            throw std::runtime_error(msg);
        }
        else if (0 == rcvBytes)
        {
            // Remote disconect recoverable case
            throw RecoverableError("recvMsg: socket disconnected"); // errno is not set
        }
    };

    uint32_t msgSize; // Message size (Header readed)
    auto recvb {recvWaitAll(sock, &msgSize, sizeof(msgSize))};
    checkRcv(recvb);

    if (MSG_MAX_SIZE < msgSize)
    {
        std::runtime_error("recvMsg: message size too long");
    }

    std::vector<char> recvMsg;
    recvMsg.resize(msgSize + 1, '\0');

    recvb = recvWaitAll(sock, &(recvMsg[0]), msgSize);
    checkRcv(recvb);

    return recvMsg;
}

std::string recvString(const int sock)
{
    auto byteMsg {recvMsg(sock)};
    return std::string(byteMsg.data());
}

} // namespace socketinterface

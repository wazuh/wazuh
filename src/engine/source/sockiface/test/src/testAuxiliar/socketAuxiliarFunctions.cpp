#include "socketAuxiliarFunctions.hpp"

#include <fcntl.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <base/logging.hpp>

#include <sockiface/unixDatagram.hpp>

using sockiface::DATAGRAM_MAX_MSG_SIZE;

int testBindUnixSocket(std::string_view path, const int socketType)
{
    /* Remove the socket's path if it already exists */
    unlink(path.data());

    /* Set-up sockaddr structure */
    struct sockaddr_un n_us;
    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path.data(), sizeof(n_us.sun_path) - 1);

    const int socketFD = socket(PF_UNIX, socketType, 0);
    if (0 > socketFD)
    {
        return UnixSocketErrorCodes::SOCKET_ERROR;
    }

    if (bind(socketFD, (struct sockaddr*)&n_us, SUN_LEN(&n_us)) < 0)
    {
        close(socketFD);
        return UnixSocketErrorCodes::BIND_ERROR;
    }

    /* Change socket's permissions */
    if (chmod(path.data(), 0660) < 0)
    {
        close(socketFD);
        return UnixSocketErrorCodes::CHMOD_ERROR;
    }

    if (SOCK_STREAM == socketType && listen(socketFD, 1) < 0)
    {
        close(socketFD);
        return UnixSocketErrorCodes::LISTEN_ERROR;
    }

    return socketFD;
}

int testAcceptConnection(const int serverSocketFD)
{
    struct sockaddr_in _nc;
    memset(&_nc, 0, sizeof(_nc));
    socklen_t _ncl = sizeof(_nc);

    const int clientSocketFD = accept(serverSocketFD, (struct sockaddr*)&_nc, &_ncl);
    if (clientSocketFD < 0)
    {
        return UnixSocketErrorCodes::ACCEPT_ERROR;
    }

    return clientSocketFD;
}

int testSocketConnect(std::string_view path, const int socketType)
{
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
    const auto socketFD {socket(PF_UNIX, socketType, 0)};
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
        /* Get current maximum size only send socketFD */
        if (getsockopt(socketFD, SOL_SOCKET, SO_SNDBUF, (void*)&len, &optlen) == -1)
        {
            len = 0;
        }

        /* Set maximum message size only recve socketFD */
        if (MSG_MAX_SIZE > len)
        {
            len = MSG_MAX_SIZE;
            if (setsockopt(socketFD,
                           SOL_SOCKET,
                           (socketType == SOCK_DGRAM) ? SO_SNDBUF : SO_RCVBUF,
                           (const void*)&len,
                           optlen)
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
        LOG_WARNING("Cannot set close-on-exec flag to socket: {} ({}).", strerror(errno), errno);
    }

    return socketFD;
}

ssize_t testRecvWaitAll(const int socketFD, void* buf, const size_t size) noexcept
{
    ssize_t offset {}; // offset in the buffer
    ssize_t recvb {};  // Recived bytes

    for (offset = 0; offset < size; offset += recvb)
    {
        recvb = recv(socketFD, (char*)buf + offset, size - offset, 0);

        if (0 >= recvb)
        {
            offset = recvb;
            break;
        }
    }

    return offset;
}

CommRetval testSendMsg(const int socketFD, const std::string& msg, const bool doSendSize)
{

    auto result {CommRetval::COMMUNICATION_ERROR};
    auto payloadSize {static_cast<uint32_t>(msg.size())};
    const auto HEADER_SIZE {sizeof(uint32_t)};

    // Validate
    if (0 >= socketFD)
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
        // MSG_NOSIGNAL prevent broken pipe signal
        bool success = true;
        if (doSendSize)
        {
            success =
                (send(socketFD, &payloadSize, HEADER_SIZE, MSG_NOSIGNAL) == HEADER_SIZE);
        }
        success =
            success
            && (send(socketFD, msg.data(), payloadSize, MSG_NOSIGNAL) == payloadSize);

        if (success)
        {
            result = CommRetval::SUCCESS;
        }
        else if (EAGAIN == errno || EWOULDBLOCK == errno)
        {
            LOG_WARNING("wdb socket is full: {} ({}).", strerror(errno), errno);
        }
        else if (EPIPE == errno)
        {
            // Recoverable case
            throw std::runtime_error("Socket is disconnected");
        }
    }

    return result;
}

inline std::vector<char> testStreamRcvMsg(const int socketFD)
{
    // Check recive msg
    const auto checkRcv = [](const ssize_t rcvBytes) {
        if (0 > rcvBytes)
        {
            const auto msg = std::string {"recvMsg: recv error : "} + strerror(errno)
                             + " (" + std::to_string(errno) + ")";
            throw std::runtime_error(msg);
        }
        else if (0 == rcvBytes)
        {
            // Remote disconect recoverable case
            throw std::runtime_error("recvMsg: socket disconnected"); // errno is not set
        }
    };

    uint32_t msgSize; // Message size (Header readed)
    auto recvb {testRecvWaitAll(socketFD, &msgSize, sizeof(msgSize))};
    checkRcv(recvb);

    if (MSG_MAX_SIZE < msgSize)
    {
        std::runtime_error("recvMsg: message size is too long");
    }

    std::vector<char> recvMsg;
    recvMsg.resize(msgSize);

    recvb = testRecvWaitAll(socketFD, &(recvMsg[0]), msgSize);
    checkRcv(recvb);

    return recvMsg;
}

inline std::vector<char> testDatagramRcvMsg(const int socketFD)
{
    std::vector<char> recvMsg;
    recvMsg.resize(DATAGRAM_MAX_MSG_SIZE);
    socklen_t len {};
    struct sockaddr_un peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));

    recvfrom(socketFD,
             &(recvMsg[0]),
             DATAGRAM_MAX_MSG_SIZE,
             0,
             (struct sockaddr*)&peer_sock,
             &len);

    return recvMsg;
}

std::vector<char> testRecvMsg(const int socketFD, const int socketType)
{
    std::vector<char> recvMsg;
    switch (socketType)
    {
        case SOCK_STREAM: recvMsg = testStreamRcvMsg(socketFD); break;
        case SOCK_DGRAM: recvMsg = testDatagramRcvMsg(socketFD); break;
        default: break;
    }

    return recvMsg;
}

std::string testRecvString(const int socketFD, const int socketType)
{
    auto byteMsg {testRecvMsg(socketFD, socketType)};
    return std::string(byteMsg.data(), byteMsg.size());
}

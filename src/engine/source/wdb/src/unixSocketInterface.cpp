
#include "unixSocketInterface.hpp"

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
ssize_t recvWaitAll(int sock, void* buf, size_t size)
{
    size_t offset {}; // offset in the buffer
    ssize_t recvb {}; // Recived bytes

    for (offset = 0; offset < size; offset += recvb)
    {
        recvb = recv(sock, (char*)buf + offset, size - offset, 0);

        switch (recvb)
        {
            // Socket disconnected
            case 0: return 0;
            case -1: return SOCKET_ERROR;
        }
    }

    return offset;
}
} // namespace

int socketConnect(const char* path)
{

    /* Socket options */
    constexpr int SOCK_TYPE {SOCK_STREAM};

    /* Config the socket address */
    struct sockaddr_un sAddr
    {
        .sun_family = AF_UNIX, .sun_path = {}
    };
    // The max path length is 108 bytes
    strncpy(sAddr.sun_path, path, sizeof(sAddr.sun_path) - 1);

    /* Get the socket fd connector */
    const int socketFD {socket(PF_UNIX, SOCK_TYPE, 0)};
    if (socketFD < 0)
    {
        const std::string msg = std::string {"Cannot create the socket: "}
                                + strerror(errno) + " (" + std::to_string(errno) + ")";

        throw std::runtime_error(msg);
    }

    /* Connect to the UNIX domain */
    if (connect(socketFD, reinterpret_cast<struct sockaddr*>(&sAddr), SUN_LEN(&sAddr))
        < 0)
    {
        close(socketFD);
        const std::string msg = std::string {"Cannot connect: "} + strerror(errno) + " ("
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
        if (len < SOCKET_BUFFER_MAX_SIZE)
        {
            len = SOCKET_BUFFER_MAX_SIZE;
            if (setsockopt(socketFD, SOL_SOCKET, SO_RCVBUF, (const void*)&len, optlen)
                == -1)
            {
                close(socketFD);
                const std::string msg = std::string {"Cannot set socket buffer size: "}
                                        + strerror(errno) + " (" + std::to_string(errno)
                                        + ")";
                throw std::runtime_error(msg);
            }
        }
    }

    // Set close-on-exec
    if (fcntl(socketFD, F_SETFD, FD_CLOEXEC) == -1)
    {
        WAZUH_LOG_WARN(
            "Cannot set close-on-exec flag to socket {} {}", strerror(errno), errno);
    }

    return (socketFD);
}

int sendMsg(int sock, const char* msg)
{
    if (msg == nullptr)
    {
        // TODO: Maybe return a NULL_PTR_MSG code
        return 0;
    }

    return sendMsg(sock, msg, strlen(msg));
}

int sendMsg(int sock, const char* msg, uint32_t size)
{
    char* buffer {nullptr};
    size_t bufferSize {HEADER_SIZE + size}; // Header + Message

    // Validate
    if (sock <= 0)
    {
        return INVALID_SOCKET;
    }
    else if (msg == nullptr)
    {
        return NULL_PTR;
    }
    else if (size == 0)
    {
        return SIZE_ZERO;
    }
    else if (size > MSG_MAX_SIZE)
    {
        return SIZE_TOO_LONG;
    }

    buffer = static_cast<char*>(malloc(bufferSize));
    // Appends header
    *(uint32_t*)buffer = size;
    // Appends message
    memcpy(buffer + HEADER_SIZE, msg, size);
    // Send the message
    errno = 0;
    int retval = send(sock, buffer, bufferSize, 0) == static_cast<ssize_t>(bufferSize)
                     ? bufferSize - HEADER_SIZE
                     : SOCKET_ERROR;
    free(buffer);

    return retval;
}

int recvMsg(int sock, char* outBuffer, uint32_t bufferSize)
{
    uint32_t msgsize; // Message size (Header readed)
    ssize_t recvb;    // Number of bytes received

    if (sock <= 0)
    {
        return (INVALID_SOCKET);
    }
    else if (outBuffer == nullptr)
    {
        return (NULL_PTR);
    }
    else if (bufferSize <= 1)
    {
        return (SIZE_ZERO);
    }

    /* Get header */
    recvb = recvWaitAll(sock, &msgsize, sizeof(msgsize));

    /* Verify header */
    switch (recvb)
    {
        case -1: return SOCKET_ERROR; break;

        case 0: return 0; break;
    }

    /* Reserve last byte for null-termination */
    if (msgsize >= bufferSize)
    {
        /* Error: the payload length is too long */
        return SIZE_TOO_LONG;
    }

    /* Get payload */
    recvb = recvWaitAll(sock, outBuffer, msgsize);

    /* Terminate string */
    if (recvb == static_cast<int32_t>(msgsize) && msgsize < bufferSize)
    {
        outBuffer[msgsize] = '\0';
    }

    return recvb;
}

} // namespace socketinterface

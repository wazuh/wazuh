
#include "unixSocketInterface.hpp"

namespace socketinterface
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
static ssize_t recvWaitAll(int sock, void* buf, size_t size)
{
    size_t offset {}; // offset in the buffer
    ssize_t recvb {}; // Recived bytes

    for (offset = 0; offset < size; offset += recvb)
    {
        recvb = recv(sock, (char*)buf + offset, size - offset, 0);

        if (recvb <= 0)
        {
            return recvb;
        }
    }

    return offset;
}

int socketConnect(const char* path)
{
    // https://github.com/wazuh/wazuh/blob/v4.3.0/src/shared/wazuhdb_op.c#L29
    // https://github.com/wazuh/wazuh/blob/v4.3.0/src/headers/defs.h#L31
    /* Socket options */
    constexpr int SOCK_TYPE {SOCK_STREAM};
    constexpr int MAX_BUF_SIZE {6144};

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
        WAZUH_LOG_ERROR("Cannot create the socket: {} ({})", strerror(errno), errno);
        return (SOCKET_ERROR);
    }

    /* Connect to the UNIX domain */
    if (connect(socketFD, (struct sockaddr*)&sAddr, SUN_LEN(&sAddr)) < 0)
    {
        WAZUH_LOG_ERROR("Cannot connect: {} ({})", strerror(errno), errno);
        close(socketFD);
        return (SOCKET_ERROR);
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
        if (len < MAX_BUF_SIZE)
        {
            len = MAX_BUF_SIZE;
            if (setsockopt(socketFD, SOL_SOCKET, SO_RCVBUF, (const void*)&len, optlen)
                == -1)
            {
                WAZUH_LOG_ERROR(
                    "Cannot set socket buffer size: {} ({})", strerror(errno), errno);
                close(socketFD);
                return SOCKET_ERROR;
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
    int retval {SOCKET_ERROR};
    char* buffer {nullptr};
    size_t bufferSize {sizeof(uint32_t) + size}; // Header + Message

    // TODO: Why a SOCKET_ERROR is returned if the msg is NULL or messageless? Maybe a 0
    // should be returned in such cases.
    if (sock <= 0 || msg == nullptr || size == 0)
    {
        return (SOCKET_ERROR);
    }

    buffer = (char*)malloc(bufferSize);
    // Adds header
    *(uint32_t*)buffer = size;
    // Appends message
    memcpy(buffer + sizeof(uint32_t), msg, size);
    errno = 0; // TODO: Is this necessary?
    retval = send(sock, buffer, bufferSize, 0) == (ssize_t)bufferSize ? bufferSize
                                                                      : SOCKET_ERROR;
    free(buffer);

    return retval;
}

int recvMsg(int sock, char* outBuffer, uint32_t bufferSize)
{
    uint32_t msgsize; // Message size (Header readed)
    ssize_t recvb;    // Number of bytes received

    if (sock < 0 || outBuffer == nullptr || bufferSize == 0)
    {
        return (SOCKET_ERROR);
    }
    /* Get header */
    recvb = recvWaitAll(sock, &msgsize, sizeof(msgsize));

    /* Verify header */
    switch (recvb)
    {
        case -1: return SOCKET_ERROR; break;

        case 0: return recvb; break;
    }

    /* Reserve last byte for null-termination */
    if (msgsize >= bufferSize)
    {
        /* Error: the payload length is too long */
        return SOCKET_ERROR;
    }

    /* Get payload */
    recvb = recvWaitAll(sock, outBuffer, msgsize);

    /* Terminate string */
    if (recvb == (int32_t)msgsize && msgsize < bufferSize)
    {
        outBuffer[msgsize] = '\0';
    }

    return recvb;
}

} // namespace socketinterface

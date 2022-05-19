#ifndef _WDB_PROTOCOL_H
#define _WDB_PROTOCOL_H

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <logging/logging.hpp>

/*
TODO readme with socket protocol description
*/

constexpr int OS_SOCKTERR = -1;

int OS_ConnectUnixDomain(const char* path)
{
    // https://github.com/wazuh/wazuh/blob/v4.3.0/src/shared/wazuhdb_op.c#L29
    constexpr int type = SOCK_STREAM;
    // https://github.com/wazuh/wazuh/blob/v4.3.0/src/headers/defs.h#L31
    constexpr int max_msg_size = 6144;

    struct sockaddr_un n_us
    {
        0
    };

    int ossock = 0;
    n_us.sun_family = AF_UNIX;

    /* Set up path */
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((ossock = socket(PF_UNIX, type, 0)) < 0)
    {
        return (OS_SOCKTERR);
    }

    /* Connect to the UNIX domain */
    if (connect(ossock, (struct sockaddr*)&n_us, SUN_LEN(&n_us)) < 0)
    {
         WAZUH_LOG_WARN("Cannot connect: {} ({})",
                       strerror(errno),
                       errno);
        close(ossock);
        return (OS_SOCKTERR);
    }

    // Set socket maximum size
    {
        int len;
        socklen_t optlen = sizeof(len);
        /* Get current maximum size only recve sock */
        if (getsockopt(ossock, SOL_SOCKET, SO_RCVBUF, (void*)&len, &optlen) ==
            -1)
        {
            len = 0;
        }

        /* Set maximum message size only recve sock */
        if (len < max_msg_size)
        {
            len = max_msg_size;
            if (setsockopt(
                    ossock, SOL_SOCKET, SO_RCVBUF, (const void*)&len, optlen) <
                0)
            {
                close(ossock);
                return OS_SOCKTERR;
            }
        }
    }

    // Set close-on-exec
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1)
    {
        WAZUH_LOG_WARN("Cannot set close-on-exec flag to socket {} {}",
                       strerror(errno),
                       errno);
    }

    return (ossock);
}



/* Receive a message from a stream socket, full message (MSG_WAITALL)
 * Returns size on success.
 * Returns -1 on socket error.
 * Returns 0 on socket disconnected or timeout.
 */
ssize_t os_recv_waitall(int sock, void * buf, size_t size) {
    size_t offset;
    ssize_t recvb;

    for (offset = 0; offset < size; offset += recvb) {
        recvb = recv(sock, buf + offset, size - offset, 0);

        if (recvb <= 0) {
            return recvb;
        }
    }

    return offset;
}

// Send secure TCP message
int OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    int retval = OS_SOCKTERR;
    void* buffer = NULL;
    size_t bufsz = size + sizeof(uint32_t);

    if (sock < 0) {
        return retval;
    }

    buffer = malloc(bufsz);
    *(uint32_t *)buffer = size;
    memcpy(buffer + sizeof(uint32_t), msg, size);
    errno = 0;
    retval = send(sock, buffer, bufsz, 0) == (ssize_t)bufsz ? 0 : OS_SOCKTERR;
    free(buffer);
    return retval;
}


/* Receive secure TCP message
 * This function reads a header containing message size as 4-byte little-endian unsigned integer.
 * Return recvval on success or OS_SOCKTERR on error.
 */
int OS_RecvSecureTCP(int sock, char * ret, uint32_t size) {
    ssize_t recvval, recvb;
    uint32_t msgsize;

    /* Get header */
    recvval = os_recv_waitall(sock, &msgsize, sizeof(msgsize));

    switch(recvval) {
        case -1:
            return recvval;
            break;

        case 0:
            return recvval;
            break;
    }

    if(msgsize > size){
        /* Error: the payload length is too long */
        return OS_SOCKTERR;
    }

    /* Get payload */
    recvb = os_recv_waitall(sock, ret, msgsize);

    /* Terminate string if there is space left */

    if (recvb == (int32_t) msgsize && msgsize < size) {
        ret[msgsize] = '\0';
    }

    return recvb;
}

#endif

#ifndef _WDB_PROTOCOL_H
#define _WDB_PROTOCOL_H

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <logging/logging.hpp>


constexpr int OS_SOCKTERR = -1;

int OS_ConnectUnixDomain(const char* path)
{
    // https://github.com/wazuh/wazuh/blob/5bae1c1830dbf11acc8a06e01f7a5a134b767760/src/shared/wazuhdb_op.c#L29
    constexpr int type = SOCK_STREAM;
    // https://github.com/wazuh/wazuh/blob/5bae1c1830dbf11acc8a06e01f7a5a134b767760/src/headers/defs.h#L31
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
        WAZUH_LOG_ERROR("{}", "Cannot set close-on-exec flag to socket");
        //mwarn("Cannot set close-on-exec flag to socket: %s (%d)",
        //      strerror(errno),
        //      errno);
    }

    return (ossock);
}

#endif

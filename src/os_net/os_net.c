/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_net Library
 * APIs for many network operations
 */

#include <errno.h>
#include "shared.h"
#include "os_net.h"
#include "wazuh_modules/wmodules.h"

/* Prototypes */
static int OS_Bindport(u_int16_t _port, unsigned int _proto, const char *_ip, int ipv6);
static int OS_Connect(u_int16_t _port, unsigned int protocol, const char *_ip, int ipv6);

/* Unix socket -- not for windows */
#ifndef WIN32

/* UNIX SOCKET */
#ifndef SUN_LEN
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
                     + strlen ((ptr)->sun_path))
#endif /* Sun_LEN */

#else /* WIN32 */
/*int ENOBUFS = 0;*/
#ifndef ENOBUFS
#define ENOBUFS 0
#endif

#endif /* WIN32*/

#define RECV_SOCK 0
#define SEND_SOCK 1


/* Bind a specific port */
static int OS_Bindport(u_int16_t _port, unsigned int _proto, const char *_ip, int ipv6)
{
    int ossock;
    struct sockaddr_in server;

#ifndef WIN32
    struct sockaddr_in6 server6;
#else
    ipv6 = 0;
#endif

    if (_proto == IPPROTO_UDP) {
        if ((ossock = socket(ipv6 == 1 ? PF_INET6 : PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            return OS_SOCKTERR;
        }
    } else if (_proto == IPPROTO_TCP) {
        int flag = 1;
        if ((ossock = socket(ipv6 == 1 ? PF_INET6 : PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            return (int)(OS_SOCKTERR);
        }

        if (setsockopt(ossock, SOL_SOCKET, SO_REUSEADDR,
                       (char *)&flag,  sizeof(flag)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    } else {
        return (OS_INVALID);
    }

    if (ipv6) {
#ifndef WIN32
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons( _port );
        server6.sin6_addr = in6addr_any;

        if (bind(ossock, (struct sockaddr *) &server6, sizeof(server6)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
#endif
    } else {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( _port );

        if ((_ip == NULL) || (_ip[0] == '\0')) {
            server.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            server.sin_addr.s_addr = inet_addr(_ip);
        }

        if (bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }

    if (_proto == IPPROTO_TCP) {
        if (listen(ossock, BACKLOG) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }

    return (ossock);
}

/* Bind a TCP port, using the OS_Bindport */
int OS_Bindporttcp(u_int16_t _port, const char *_ip, int ipv6)
{
    return (OS_Bindport(_port, IPPROTO_TCP, _ip, ipv6));
}

/* Bind a UDP port, using the OS_Bindport */
int OS_Bindportudp(u_int16_t _port, const char *_ip, int ipv6)
{
    return (OS_Bindport(_port, IPPROTO_UDP, _ip, ipv6));
}

#ifndef WIN32
/* Bind to a Unix domain, using DGRAM sockets */
int OS_BindUnixDomain(const char *path, int type, int max_msg_size)
{
    struct sockaddr_un n_us;
    int ossock = 0;

    /* Make sure the path isn't there */
    unlink(path);

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((ossock = socket(PF_UNIX, type, 0)) < 0) {
        return (OS_SOCKTERR);
    }

    if (bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Change permissions */
    if (chmod(path, 0660) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    if (type == SOCK_STREAM && listen(ossock, 128) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set socket maximum size
    if (OS_SetSocketSize(ossock, RECV_SOCK, max_msg_size) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set close-on-exec
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1) {
        mwarn("Cannot set close-on-exec flag to socket: %s (%d)", strerror(errno), errno);
    }

    return (ossock);
}

/* Open a client Unix domain socket
 * ("/tmp/lala-socket",0666));
 */
int OS_ConnectUnixDomain(const char *path, int type, int max_msg_size)
{
    struct sockaddr_un n_us;

    int ossock = 0;

    memset(&n_us, 0, sizeof(n_us));

    n_us.sun_family = AF_UNIX;

    /* Set up path */
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((ossock = socket(PF_UNIX, type, 0)) < 0) {
        return (OS_SOCKTERR);
    }

    /* Connect to the UNIX domain */
    if (connect(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set socket maximum size
    if (OS_SetSocketSize(ossock, SEND_SOCK, max_msg_size) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set close-on-exec
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1) {
        mwarn("Cannot set close-on-exec flag to socket: %s (%d)", strerror(errno), errno);
    }

    return (ossock);
}

int OS_getsocketsize(int ossock)
{
    int len = 0;
    socklen_t optlen = sizeof(len);

    /* Get current maximum size */
    if (getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1) {
        return (OS_SOCKTERR);
    }

    return (len);
}

#endif

/* Open a TCP/UDP client socket */
static int OS_Connect(u_int16_t _port, unsigned int protocol, const char *_ip, int ipv6)
{
    int ossock;
    int max_msg_size = OS_MAXSTR + 512;
    struct sockaddr_in server;
#ifndef WIN32
    struct sockaddr_in6 server6;
#else
    ipv6 = 0;
#endif

    if (protocol == IPPROTO_TCP) {
        if ((ossock = socket(ipv6 == 1 ? PF_INET6 : PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            return (OS_SOCKTERR);
        }
    } else if (protocol == IPPROTO_UDP) {
        if ((ossock = socket(ipv6 == 1 ? PF_INET6 : PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            return (OS_SOCKTERR);
        }
    } else {
        return (OS_INVALID);
    }

    if ((_ip == NULL) || (_ip[0] == '\0')) {
        OS_CloseSocket(ossock);
        return (OS_INVALID);
    }

    if (ipv6 == 1) {
#ifndef WIN32
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons( _port );
        inet_pton(AF_INET6, _ip, &server6.sin6_addr.s6_addr);

        if (connect(ossock, (struct sockaddr *)&server6, sizeof(server6)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
#endif
    } else {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( _port );
        server.sin_addr.s_addr = inet_addr(_ip);

        if (connect(ossock, (struct sockaddr *)&server, sizeof(server)) < 0) {
#ifdef WIN32
            int error = WSAGetLastError();
#endif
            OS_CloseSocket(ossock);
#ifdef WIN32
            WSASetLastError(error);
#endif
            return (OS_SOCKTERR);
        }
    }

    // Set socket maximum size
    if (OS_SetSocketSize(ossock, RECV_SOCK, max_msg_size) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }
    if (OS_SetSocketSize(ossock, SEND_SOCK, max_msg_size) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    return (ossock);
}

/* Open a TCP socket */
int OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6)
{
    return (OS_Connect(_port, IPPROTO_TCP, _ip, ipv6));
}

/* Open a UDP socket */
int OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6)
{
    int sock = OS_Connect(_port, IPPROTO_UDP, _ip, ipv6);

#ifdef HPUX
    if (sock >= 0) {
        int flags;
        flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    return sock;
}

/* Send a TCP packet (through an open socket) */
int OS_SendTCP(int socket, const char *msg)
{
    if ((send(socket, msg, strlen(msg), 0)) <= 0) {
        return (OS_SOCKTERR);
    }

    return (0);
}

/* Send a TCP packet of a specific size (through a open socket) */
int OS_SendTCPbySize(int socket, int size, const char *msg)
{
    if ((send(socket, msg, size, 0)) < size) {
        return (OS_SOCKTERR);
    }

    return (0);
}

/* Send a UDP packet of a specific size (through an open socket) */
int OS_SendUDPbySize(int socket, int size, const char *msg)
{
    unsigned int i = 0;

    /* Maximum attempts is 5 */
    while ((send(socket, msg, size, 0)) < 0) {
        if ((errno != ENOBUFS) || (i >= 5)) {
            return (OS_SOCKTERR);
        }

        i++;
        minfo("Remote socket busy, waiting %d s.", i);
        sleep(i);
    }

    return (0);
}

/* Accept a TCP connection */
int OS_AcceptTCP(int socket, char *srcip, size_t addrsize)
{
    int clientsocket;
    struct sockaddr_in _nc;
    socklen_t _ncl;

    memset(&_nc, 0, sizeof(_nc));
    _ncl = sizeof(_nc);

    if ((clientsocket = accept(socket, (struct sockaddr *) &_nc,
                               &_ncl)) < 0) {
        return (-1);
    }

    strncpy(srcip, inet_ntoa(_nc.sin_addr), addrsize - 1);
    srcip[addrsize - 1] = '\0';

    return (clientsocket);
}

/* Receive a TCP packet (from an open socket) */
char *OS_RecvTCP(int socket, int sizet)
{
    char *ret;

    ret = (char *) calloc((sizet), sizeof(char));
    if (ret == NULL) {
        return (NULL);
    }

    if (recv(socket, ret, sizet - 1, 0) <= 0) {
        free(ret);
        return (NULL);
    }

    return (ret);
}

/* Receive a TCP packet (from an open socket) */
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet)
{
    int retsize;

    if ((retsize = recv(socket, buffer, sizet - 1, 0)) > 0) {
        buffer[retsize] = '\0';
        return (0);
    }
    return (-1);
}

/* Receive a UDP packet */
char *OS_RecvUDP(int socket, int sizet)
{
    char *ret;

    ret = (char *) calloc((sizet), sizeof(char));
    if (ret == NULL) {
        return (NULL);
    }

    if ((recv(socket, ret, sizet - 1, 0)) < 0) {
        free(ret);
        return (NULL);
    }

    return (ret);
}

/* Receives a message from a connected UDP socket */
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size)
{
    int recv_b;

    recv_b = recv(socket, buffer, buffer_size, 0);
    if (recv_b < 0) {
        return (0);
    }

    buffer[recv_b] = '\0';

    return (recv_b);
}

#ifndef WIN32
/* Receive a message from a Unix socket */
int OS_RecvUnix(int socket, int sizet, char *ret)
{
    struct sockaddr_un n_us;
    socklen_t us_l = sizeof(n_us);
    ssize_t recvd;
    ret[sizet] = '\0';

    if ((recvd = recvfrom(socket, ret, sizet - 1, 0,
                          (struct sockaddr *)&n_us, &us_l)) < 0) {
        return (0);
    }

    ret[recvd] = '\0';
    return ((int)recvd);
}

/* Send a message using a Unix socket
 * Returns the OS_SOCKETERR if it fails
 */
int OS_SendUnix(int socket, const char *msg, int size)
{
    if (size == 0) {
        size = strlen(msg) + 1;
    }

    if (send(socket, msg, size, 0) < size) {
        if (errno == ENOBUFS) {
            return (OS_SOCKBUSY);
        }

        return (OS_SOCKTERR);
    }

    return (OS_SUCCESS);
}
#endif

/* Calls gethostbyname (tries x attempts) */
char *OS_GetHost(const char *host, unsigned int attempts)
{
    unsigned int i = 0;
    size_t sz;
    char *ip;
    struct hostent *h;

    if (host == NULL) {
        return (NULL);
    }

    while (i <= attempts) {
        if ((h = gethostbyname(host)) == NULL) {
            sleep(i++);
            continue;
        }

        sz = strlen(inet_ntoa(*((struct in_addr *)h->h_addr))) + 1;
        if ((ip = (char *) calloc(sz, sizeof(char))) == NULL) {
            return (NULL);
        }

        strncpy(ip, inet_ntoa(*((struct in_addr *)h->h_addr)), sz - 1);

        return (ip);
    }

    return (NULL);
}

int OS_CloseSocket(int socket)
{
#ifdef WIN32
    return (closesocket(socket));
#else
    return (close(socket));
#endif /* WIN32 */
}

int OS_SetRecvTimeout(int socket, long seconds, long useconds)
{
#ifdef WIN32
    DWORD ms = seconds * 1000 + useconds / 1000;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const void *)&ms, sizeof(ms));
#else
    struct timeval tv = { seconds, useconds };
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv));
#endif
}

int OS_SetSendTimeout(int socket, int seconds)
{
#ifdef WIN32
    DWORD ms = seconds * 1000;
    return setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const void *)&ms, sizeof(ms));
#else
    struct timeval tv = { seconds, 0 };
    return setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tv, sizeof(tv));
#endif
}

/* Send secure TCP message
 * This function prepends a header containing message size as 4-byte little-endian unsigned integer.
 * Return 0 on success or OS_SOCKTERR on error.
 */
int OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    int retval;
    void * buffer;
    size_t bufsz = size + sizeof(uint32_t);

    os_malloc(bufsz, buffer);
    *(uint32_t *)buffer = wnet_order(size);
    memcpy(buffer + sizeof(uint32_t), msg, size);
    retval = send(sock, buffer, bufsz, 0) == (ssize_t)bufsz ? 0 : OS_SOCKTERR;

    free(buffer);
    return retval;
}


/* Receive secure TCP message
 * This function reads a header containing message size as 4-byte little-endian unsigned integer.
 * Return recvval on success or OS_SOCKTERR on error.
 */
int OS_RecvSecureTCP(int sock, char * ret,uint32_t size) {
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

    msgsize = wnet_order(msgsize);

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


ssize_t OS_RecvSecureTCP_Dynamic(int sock, char **ret) {
    ssize_t recvval, recvmsg = 0;
    char *dyn_buffer;
    const size_t bufsz = 512;
    char static_buf[bufsz+1];
    uint64_t msgsize;

    recvval = recv(sock, static_buf, bufsz, 0);

    switch(recvval){

        case -1:
            return -1;

        case 0:
            return 0;
    }

    static_buf[recvval] = '\0';

    if (static_buf[0] == '!') {
        char * c;
        char * data;

        if (c = strchr(static_buf, ' '), c) {
            *c = '\0';
            data = c + 1;

            if (msgsize = strtoul(static_buf + 1, &c, 10), *c) {
                merror("At OS_RecvSecureTCP(): invalid message size");
                return -1;
            }

            if(msgsize > MAX_DYN_STR) {
                return OS_MAXLEN;
            }
        } else {
            merror("At OS_RecvSecureTCP(): invalid message received");
            return -1;
        }

        os_malloc(msgsize + 1, *ret);
        memcpy(*ret, data, msgsize);
        recvval = strlen(data);

        if ((uint32_t)recvval < msgsize) {
            recvmsg = os_recv_waitall(sock, *ret + recvval, msgsize - recvval);

            switch(recvmsg){
                case -1:
                case 0:
                    free(*ret);
                    return 0;
            }
        }
        *(*ret + msgsize) = '\0';
        return msgsize;
    }
    else {
        os_malloc(OS_MAXSTR + 2, dyn_buffer);

        recvmsg = recv(sock, dyn_buffer + 1, OS_MAXSTR, 0);

        switch(recvmsg){
            case -1:
                free(dyn_buffer);
                return -1;

            case 0:
                free(dyn_buffer);
                return 0;
        }

        dyn_buffer[recvmsg + 1] = '\0';
        *ret = dyn_buffer;

        return recvmsg;
    }
}

// Byte ordering

uint32_t wnet_order(uint32_t value) {
#if defined(__sparc__) || defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || defined(OS_BIG_ENDIAN)
    return (value >> 24) | (value << 24) | ((value & 0xFF0000) >> 8) | ((value & 0xFF00) << 8);
#else
    return value;
#endif
}


uint32_t wnet_order_big(uint32_t value) {
#if defined(__sparc__) || defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || defined(OS_BIG_ENDIAN)
    return value;
#else
    return (value >> 24) | (value << 24) | ((value & 0xFF0000) >> 8) | ((value & 0xFF00) << 8);
#endif
}

/* Set the maximum buffer size for the socket */
int OS_SetSocketSize(int sock, int mode, int max_msg_size) {

    int len;
    socklen_t optlen = sizeof(len);

    if (mode == RECV_SOCK) {

        /* Get current maximum size */
        if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (void *)&len, &optlen) == -1) {
            return -1;
        }

        /* Set maximum message size */
        if (len < max_msg_size) {
            len = max_msg_size;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const void *)&len, optlen) < 0) {
                return -1;
            }
        }

    } else if (mode == SEND_SOCK) {

        /* Get current maximum size */
        if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (void *)&len, &optlen) == -1) {
            return -1;
        }

        /* Set maximum message size */
        if (len < max_msg_size) {
            len = max_msg_size;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const void *)&len, optlen) < 0) {
                return -1;
            }
        }
    }

    return 0;
}


/* Send secure TCP to Cluster message
 * Return 0 on success or OS_SOCKTERR on error.
 */
int OS_SendSecureTCPCluster(int sock, const void * command, const void * payload, size_t length) {
    const unsigned COMMAND_SIZE = 12;
    const unsigned HEADER_SIZE =  8;
    const unsigned MAX_PAYLOAD_SIZE = 1000000;
    int retval;
    char * buffer = NULL;
    uint32_t counter = (uint32_t)os_random();
    size_t cmd_length = 0;
    size_t buffer_size = 0;

    if(!command){
        merror("Empty command, not sending message to cluster");
        return -1;
    }

    if (length > MAX_PAYLOAD_SIZE) {
        merror("Data of length %u exceeds maximum allowed %u", (unsigned)length, MAX_PAYLOAD_SIZE);
        return -1;
    }

    cmd_length = strlen(command);

    if(cmd_length > COMMAND_SIZE){
        merror("Command of length %u exceeds maximum allowed %u", (unsigned)cmd_length, COMMAND_SIZE);
        return -1;
    }

    // Cluster message: [counter:4][length:4][command:12][payload]
    buffer_size = HEADER_SIZE + COMMAND_SIZE + length;
    os_malloc(buffer_size, buffer);
    *(uint32_t *)buffer = wnet_order_big(counter);
    *(uint32_t *)(buffer + 4) = wnet_order_big(length);
    memcpy(buffer + HEADER_SIZE, command, cmd_length);
    buffer[HEADER_SIZE + cmd_length] = ' ';
    memset(buffer + HEADER_SIZE + cmd_length + 1, '-', COMMAND_SIZE - cmd_length - 1);
    memcpy(buffer + HEADER_SIZE + COMMAND_SIZE, payload, length);

    retval = send(sock, buffer, buffer_size, 0) == (ssize_t)buffer_size ? 0 : OS_SOCKTERR;

    free(buffer);
    return retval;
}


/* Receive secure TCP message
 * Return recvval on success or OS_SOCKTERR on error.
 */
int OS_RecvSecureClusterTCP(int sock, char * ret, size_t length) {
    int recvval;
    const unsigned CMD_SIZE = 12;
    const uint32_t HEADER_SIZE = 8 + CMD_SIZE;
    uint32_t size = 0;
    char buffer[HEADER_SIZE];

    recvval = os_recv_waitall(sock, buffer, HEADER_SIZE);

    switch(recvval){
        case -1:
            return recvval;
            break;

        case 0:
            return recvval;
            break;

        default:
            if ((uint32_t)recvval != HEADER_SIZE) {
                return -1;
            }
    }

    size = wnet_order_big(*(uint32_t*)(buffer + 4));

    if (size > length) {
        mwarn("Cluster message size (%u) exceeds buffer length (%u)", (unsigned)size, (unsigned)length);
        return -1;
    }

    /* Read the payload */
    return os_recv_waitall(sock, ret, size);
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

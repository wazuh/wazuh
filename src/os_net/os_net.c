/* @(#) $Id: ./src/os_net/os_net.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */

/* OS_net Library.
 * APIs for many network operations.
 */




#include "shared.h"
#include "os_net.h"




/* Unix socket -- not for windows */
#ifndef WIN32
struct sockaddr_un n_us;
socklen_t us_l = sizeof(n_us);

/* UNIX SOCKET */
#ifndef SUN_LEN
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
		                      + strlen ((ptr)->sun_path))
#endif /* Sun_LEN */

#else
int ENOBUFS = 0;
#endif /* WIN32*/


/* OS_Bindport v 0.2, 2005/02/11
 * Bind a specific port
 * v0.2: Added REUSEADDR.
 */
int OS_Bindport(char *_port, unsigned int _proto, char *_ip)
{
    int ossock, s;
    struct addrinfo hints, *result, *rp;


    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_protocol = _proto;
    if(_proto == IPPROTO_UDP)
    {
        hints.ai_socktype = SOCK_DGRAM;
    }
    else if(_proto == IPPROTO_TCP)
    {
        hints.ai_socktype = SOCK_STREAM;
    }
    else
    {
        return(OS_INVALID);
    }
    hints.ai_flags = AI_PASSIVE;

    s = getaddrinfo(_ip, _port, &hints, &result);
    if (s != 0)
    {
        verbose("getaddrinfo: %s", gai_strerror(s));
        return(OS_INVALID);
    }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or bind(2)) fails, we (close the socket
              and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        ossock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (ossock == -1)
        {
            continue;
        } 
        if(_proto == IPPROTO_TCP)
        {
            int flag = 1;
            if(setsockopt(ossock, SOL_SOCKET, SO_REUSEADDR,
                          (char *)&flag, sizeof(flag)) < 0)
            {
                return(OS_SOCKTERR);
            }
        } 
        if(bind(ossock, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            break;                  /* Success */
        }
    }
    if (rp == NULL)
    {               /* No address succeeded */
        return(OS_SOCKTERR);
    }

    freeaddrinfo(result);           /* No longer needed */

    if(_proto == IPPROTO_TCP)
    {
        if(listen(ossock, 32) < 0)
        {
            return(OS_SOCKTERR);
        }
    }

    return(ossock);
}


/* OS_Bindporttcp v 0.1
 * Bind a TCP port, using the OS_Bindport
 */
int OS_Bindporttcp(char *_port, char *_ip)
{
    return(OS_Bindport(_port, IPPROTO_TCP, _ip));
}


/* OS_Bindportudp v 0.1
 * Bind a UDP port, using the OS_Bindport
 */
int OS_Bindportudp(char *_port, char *_ip)
{
    return(OS_Bindport(_port, IPPROTO_UDP, _ip));
}

#ifndef WIN32
/* OS_BindUnixDomain v0.1, 2004/07/29
 * Bind to a Unix domain, using DGRAM sockets
 */
int OS_BindUnixDomain(char * path, int mode, int max_msg_size)
{
    int len;
    int ossock = 0;
    socklen_t optlen = sizeof(len);

    /* Making sure the path isn't there */
    unlink(path);

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path)-1);

    if((ossock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        return(OS_SOCKTERR);

    if(bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0)
    {
        close(ossock);
        return(OS_SOCKTERR);
    }

    /* Changing permissions */
    chmod(path,mode);


    /* Getting current maximum size */
    if(getsockopt(ossock, SOL_SOCKET, SO_RCVBUF, &len, &optlen) == -1)
        return(OS_SOCKTERR);


    /* Setting socket opt */
    if(len < max_msg_size)
    {
        len = max_msg_size;
        setsockopt(ossock, SOL_SOCKET, SO_RCVBUF, &len, optlen);
    }

    return(ossock);
}

/* OS_ConnectUnixDomain v0.1, 2004/07/29
 * Open a client Unix domain socket
 * ("/tmp/lala-socket",0666));
 *
 */
int OS_ConnectUnixDomain(char * path, int max_msg_size)
{
    int len;
    int ossock = 0;
    socklen_t optlen = sizeof(len);

    memset(&n_us, 0, sizeof(n_us));

    n_us.sun_family = AF_UNIX;

    /* Setting up path */
    strncpy(n_us.sun_path,path,sizeof(n_us.sun_path)-1);	

    if((ossock = socket(AF_UNIX, SOCK_DGRAM,0)) < 0)
        return(OS_SOCKTERR);


    /* Connecting to the UNIX domain.
     * We can use "send" after that
     */
    if(connect(ossock,(struct sockaddr *)&n_us,SUN_LEN(&n_us)) < 0)
        return(OS_SOCKTERR);


    /* Getting current maximum size */
    if(getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1)
        return(OS_SOCKTERR);


    /* Setting maximum message size */
    if(len < max_msg_size)
    {
        len = max_msg_size;
        setsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, optlen);
    }


    /* Returning the socket */	
    return(ossock);
}


int OS_getsocketsize(int ossock)
{
    int len = 0;
    socklen_t optlen = sizeof(len);

    /* Getting current maximum size */
    if(getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1)
        return(OS_SOCKTERR);

    return(len);
}

#endif

/* OS_Connect v 0.1, 2004/07/21
 * Open a TCP/UDP client socket
 */
int OS_Connect(char *_port, unsigned int protocol, char *_ip)
{
    int ossock, s;
    struct addrinfo hints, *result, *rp;

    if((_ip == NULL)||(_ip[0] == '\0'))
        return(OS_INVALID);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_protocol = protocol;
    if(protocol == IPPROTO_TCP)
    {
        hints.ai_socktype = SOCK_STREAM;
    }
    else if(protocol == IPPROTO_UDP)
    {
        hints.ai_socktype = SOCK_DGRAM;
    }
    else
        return(OS_INVALID);
    hints.ai_flags = 0;

    s = getaddrinfo(_ip, _port, &hints, &result);
    if (s != 0)
    {
        verbose("getaddrinfo: %s", gai_strerror(s));
        return(OS_INVALID);
    }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        ossock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (ossock == -1)
        {
            continue;
        } 
        if (connect(ossock, rp->ai_addr, rp->ai_addrlen) != -1)
        {
            break;                  /* Success */
        }
    }
    if (rp == NULL)
    {               /* No address succeeded */
        return(OS_SOCKTERR);
    }

    freeaddrinfo(result);           /* No longer needed */

    #ifdef HPUX
    {
    int flags;
    flags = fcntl(ossock,F_GETFL,0);
    fcntl(ossock, F_SETFL, flags | O_NONBLOCK);
    }
    #endif

    return(ossock);
}


/* OS_ConnectTCP, v0.1
 * Open a TCP socket
 */
int OS_ConnectTCP(char *_port, char *_ip)
{
    return(OS_Connect(_port, IPPROTO_TCP, _ip));
}


/* OS_ConnectUDP, v0.1
 * Open a UDP socket
 */
int OS_ConnectUDP(char *_port, char *_ip)
{
    return(OS_Connect(_port, IPPROTO_UDP, _ip));
}

/* OS_SendTCP v0.1, 2004/07/21
 * Send a TCP packet (in a open socket)
 */
int OS_SendTCP(int socket, char *msg)
{
    if((send(socket, msg, strlen(msg),0)) <= 0)
        return (OS_SOCKTERR);

    return(0);
}

/* OS_SendTCPbySize v0.1, 2004/07/21
 * Send a TCP packet (in a open socket) of a specific size
 */
int OS_SendTCPbySize(int socket, int size, char *msg)
{
    if((send(socket, msg, size, 0)) < size)
        return (OS_SOCKTERR);

    return(0);
}


/* OS_SendUDPbySize v0.1, 2004/07/21
 * Send a UDP packet (in a open socket) of a specific size
 */
int OS_SendUDPbySize(int socket, int size, char *msg)
{
    int i = 0;

    /* Maximum attempts is 5 */
    while((send(socket,msg,size,0)) < 0)
    {
        if((errno != ENOBUFS) || (i >= 5))
        {
            return(OS_SOCKTERR);
        }

        i++;
        merror("%s: INFO: Remote socket busy, waiting %d s.", __local_name, i);
        sleep(i);
    }

    return(0);
}



/* OS_AcceptTCP v0.1, 2005/01/28
 * Accept a TCP connection
 */
int OS_AcceptTCP(int socket, char *srcip, int addrsize)
{
    int clientsocket;
    struct sockaddr_storage _nc;
    socklen_t _ncl;

    memset(&_nc, 0, sizeof(_nc));
    _ncl = sizeof(_nc);

    if((clientsocket = accept(socket, (struct sockaddr *) &_nc,
                    &_ncl)) < 0)
        return(-1);	

    satop((struct sockaddr *) &_nc, srcip, addrsize -1);
    srcip[addrsize -1]='\0';

    return(clientsocket);
}


/* OS_RecvTCP v0.1, 2004/07/21
 * Receive a TCP packet (in a open socket)
 */
char *OS_RecvTCP(int socket, int sizet)
{
    char *ret;

    int retsize=0;

    ret = (char *) calloc((sizet), sizeof(char));
    if(ret == NULL)
        return(NULL);

    if((retsize = recv(socket, ret, sizet-1,0)) <= 0)
        return(NULL);

    return(ret);
}


/* OS_RecvTCPBuffer v0.1, 2004/07/21
 * Receive a TCP packet (in a open socket)
 */
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet)
{
    int retsize = 0;

    while(!retsize)
    {
        retsize = recv(socket, buffer, sizet -1, 0);
        if(retsize > 0)
        {
            buffer[retsize] = '\0';
            return(0);
        }
        return(-1);
    }
    return(-1);
}




/* OS_RecvUDP v 0.1, 2004/07/20
 * Receive a UDP packet
 */
char *OS_RecvUDP(int socket, int sizet)
{
    char *ret;

    ret = (char *) calloc((sizet), sizeof(char));
    if(ret == NULL)
        return(NULL);

    if((recv(socket,ret,sizet-1,0))<0)
        return(NULL);

    return(ret);
}


/* OS_RecvConnUDP v0.1
 * Receives a message from a connected UDP socket
 */
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size)
{
    int recv_b;

    recv_b = recv(socket, buffer, buffer_size, 0);
    if(recv_b < 0)
        return(0);

    return(recv_b);
}


#ifndef WIN32
/* OS_RecvUnix, v0.1, 2004/07/29
 * Receive a message using a Unix socket
 */
int OS_RecvUnix(int socket, int sizet, char *ret)
{
    ssize_t recvd;
    if((recvd = recvfrom(socket, ret, sizet -1, 0,
                         (struct sockaddr*)&n_us,&us_l)) < 0)
        return(0);

    ret[recvd] = '\0';
    return((int)recvd);
}


/* OS_SendUnix, v0.1, 2004/07/29
 * Send a message using a Unix socket.
 * Returns the OS_SOCKETERR if it
 */
int OS_SendUnix(int socket, char * msg, int size)
{
    if(size == 0)
        size = strlen(msg)+1;

    if(send(socket, msg, size,0) < size)
    {
        if(errno == ENOBUFS)
            return(OS_SOCKBUSY);

        return(OS_SOCKTERR);
    }

    return(OS_SUCCESS);
}
#endif


/* OS_GetHost, v0.1, 2005/01/181
 * Calls getaddrinfo (tries x attempts)
 */
char *OS_GetHost(char *host, int attempts)
{
    int i = 0;
    int error;

    char *ip;
    struct addrinfo *hai, *result;

    if(host == NULL)
        return(NULL);

    while(i <= attempts)
    {
        if((error = getaddrinfo(host, NULL, NULL, &result)) != 0)
        {
            sleep(i++);
            continue;
        }
        
        if((ip = (char *) calloc(IPSIZE, sizeof(char))) == NULL)
            return(NULL);

        hai = result;
        satop(hai->ai_addr, ip, IPSIZE);

        freeaddrinfo(result);
        return(ip);
    }

    return(NULL);
}

/* satop(struct sockaddr *sa, char *dst, socklen_t size) 
 * Convert a sockaddr to a printable address.
 */
int satop(struct sockaddr *sa, char *dst, socklen_t size)
{
    sa_family_t af;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;

    af = sa->sa_family;

    switch (af)
    {
    case AF_INET:
        sa4 = (struct sockaddr_in *) sa;
        inet_ntop(af, (const void *) &(sa4->sin_addr), dst, size);
        return(0);
    case AF_INET6:
        sa6 = (struct sockaddr_in6 *) sa;
        inet_ntop(af, (const void *) &(sa6->sin6_addr), dst, size);
        return(0);
    default:  
        *dst = '\0';
        return(-1);     
    }

}

/* EOF */

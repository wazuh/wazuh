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



#include <errno.h>
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

#else /* WIN32 */
/*int ENOBUFS = 0;*/
# ifndef ENOBUFS
# define ENOBUFS 0
# endif

#endif /* WIN32*/


/* OS_Bindport v 0.2, 2005/02/11
 * Bind a specific port
 * v0.2: Added REUSEADDR.
 */
int OS_Bindport(unsigned int _port, unsigned int _proto, char *_ip, int ipv6)
{
    int ossock;
    struct sockaddr_in server;

    #ifndef WIN32
    struct sockaddr_in6 server6;
    #else
    ipv6 = 0;
    #endif


    if(_proto == IPPROTO_UDP)
    {
        if((ossock = socket(ipv6 == 1?PF_INET6:PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        {
            return OS_SOCKTERR;
        }
    }
    else if(_proto == IPPROTO_TCP)
    {
        int flag = 1;
        if((ossock = socket(ipv6 == 1?PF_INET6:PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            return(int)(OS_SOCKTERR);
        }

        if(setsockopt(ossock, SOL_SOCKET, SO_REUSEADDR,
                              (char *)&flag,  sizeof(flag)) < 0)
        {
            return(OS_SOCKTERR);
        }
    }
    else
    {
        return(OS_INVALID);
    }

    if(ipv6)
    {
        #ifndef WIN32
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons( _port );
        server6.sin6_addr = in6addr_any;


        if(bind(ossock, (struct sockaddr *) &server6, sizeof(server6)) < 0)
        {
            return(OS_SOCKTERR);
        }
        #endif
    }
    else
    {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( _port );


        if((_ip == NULL)||(_ip[0] == '\0'))
            server.sin_addr.s_addr = htonl(INADDR_ANY);
        else
            server.sin_addr.s_addr = inet_addr(_ip);


        if(bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0)
        {
            return(OS_SOCKTERR);
        }
    }



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
int OS_Bindporttcp(unsigned int _port, char *_ip, int ipv6)
{
    return(OS_Bindport(_port, IPPROTO_TCP, _ip, ipv6));
}


/* OS_Bindportudp v 0.1
 * Bind a UDP port, using the OS_Bindport
 */
int OS_Bindportudp(unsigned int _port, char *_ip, int ipv6)
{
    return(OS_Bindport(_port, IPPROTO_UDP, _ip, ipv6));
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
int OS_Connect(unsigned int _port, unsigned int protocol, char *_ip, int ipv6)
{
    int ossock;
    struct sockaddr_in server;

    #ifndef WIN32
    struct sockaddr_in6 server6;
    #else
    ipv6 = 0;
    #endif

    if(protocol == IPPROTO_TCP)
    {
        if((ossock = socket(ipv6 == 1?PF_INET6:PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
            return(OS_SOCKTERR);
    }
    else if(protocol == IPPROTO_UDP)
    {
        if((ossock = socket(ipv6 == 1?PF_INET6:PF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
            return(OS_SOCKTERR);
    }
    else
        return(OS_INVALID);



    #ifdef HPUX
    {
    int flags;
    flags = fcntl(ossock,F_GETFL,0);
    fcntl(ossock, F_SETFL, flags | O_NONBLOCK);
    }
    #endif



    if((_ip == NULL)||(_ip[0] == '\0'))
        return(OS_INVALID);


    if(ipv6 == 1)
    {
        #ifndef WIN32
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons( _port );
        inet_pton(AF_INET6, _ip, &server6.sin6_addr.s6_addr);

        if(connect(ossock,(struct sockaddr *)&server6, sizeof(server6)) < 0)
            return(OS_SOCKTERR);
        #endif
    }
    else
    {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( _port );
        server.sin_addr.s_addr = inet_addr(_ip);


        if(connect(ossock,(struct sockaddr *)&server, sizeof(server)) < 0)
            return(OS_SOCKTERR);
    }


    return(ossock);
}


/* OS_ConnectTCP, v0.1
 * Open a TCP socket
 */
int OS_ConnectTCP(unsigned int _port, char *_ip, int ipv6)
{
    return(OS_Connect(_port, IPPROTO_TCP, _ip, ipv6));
}


/* OS_ConnectUDP, v0.1
 * Open a UDP socket
 */
int OS_ConnectUDP(unsigned int _port, char *_ip, int ipv6)
{
    return(OS_Connect(_port, IPPROTO_UDP, _ip, ipv6));
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
    struct sockaddr_in _nc;
    socklen_t _ncl;

    memset(&_nc, 0, sizeof(_nc));
    _ncl = sizeof(_nc);

    if((clientsocket = accept(socket, (struct sockaddr *) &_nc,
                    &_ncl)) < 0)
        return(-1);	

    strncpy(srcip, inet_ntoa(_nc.sin_addr),addrsize -1);
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
 * Calls gethostbyname (tries x attempts)
 */
char *OS_GetHost(char *host, int attempts)
{
    int i = 0;
    int sz;

    char *ip;
    struct hostent *h;

    if(host == NULL)
        return(NULL);

    while(i <= attempts)
    {
        if((h = gethostbyname(host)) == NULL)
        {
            sleep(i++);
            continue;
        }

        sz = strlen(inet_ntoa(*((struct in_addr *)h->h_addr)))+1;
        if((ip = (char *) calloc(sz, sizeof(char))) == NULL)
            return(NULL);

        strncpy(ip,inet_ntoa(*((struct in_addr *)h->h_addr)), sz-1);

        return(ip);
    }

    return(NULL);
}

/* EOF */

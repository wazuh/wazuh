/*      $OSSEC, os_net.c, v0.3, 2005/02/11, Daniel B. Cid$      */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* OS_net Library. 
 * APIs for many network operations.
 * Available at http://www.ossec.net/c/os_net/
 */
 
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
 
#include <sys/types.h>
#include <sys/stat.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "os_err.h"

#include "os_net.h"

/* ** Not thread safe ** */
struct sockaddr_in _c;	    /* Client socket */
socklen_t _cl;                    /* Client socket length */
struct sockaddr_un n_us;    /* Unix socket  */

/* UNIX SOCKET */
#ifndef SUN_LEN
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
		                      + strlen ((ptr)->sun_path))
#endif

/* OS_Bindport v 0.2, 2005/02/11
 * Bind a specific port
 * v0.2: Added REUSEADDR.
 */
int OS_Bindport(unsigned int _port,unsigned int _proto,char *_ip)
{
    int ossock;
    struct sockaddr_in server;

    if(_proto == IPPROTO_UDP)
    {
        if((ossock = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
            return OS_SOCKTERR;
    }
    else if(_proto == IPPROTO_TCP)
    {
        int flag=1;
        if((ossock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
            return(int)(OS_SOCKTERR);
            
        if(setsockopt(ossock, SOL_SOCKET,SO_REUSEADDR, (char *)&flag,
                    sizeof(flag)) < 0)
            return(OS_SOCKTERR);
    }
    else
        return(OS_INVALID);

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons( _port );

    if((_ip == NULL)||(_ip[0] == '\0'))
        server.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        server.sin_addr.s_addr = inet_addr(_ip);

    if(bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0)
        return(OS_SOCKTERR);

    if(_proto == IPPROTO_TCP)
    {
        if(listen(ossock,32) < 0)
            return(OS_SOCKTERR);
    }
    
    _cl = sizeof(_c);
    return(ossock);
}


/* OS_Bindporttcp v 0.1
 * Bind a TCP port, using the OS_Bindport
 */
int OS_Bindporttcp(unsigned int _port, char *_ip)
{
    return(OS_Bindport(_port, IPPROTO_TCP, _ip));
}


/* OS_Bindportudp v 0.1
 * Bind a UDP port, using the OS_Bindport
 */
int OS_Bindportudp(unsigned int _port, char *_ip)
{
    return(OS_Bindport(_port, IPPROTO_UDP, _ip));
}

/* OS_BindUnixDomain v0.1, 2004/07/29
 * Bind to a Unix domain, using DGRAM sockets
 */
int OS_BindUnixDomain(char * path, int mode)
{
    int ossock = 0;

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path)-1);

    if((ossock = socket(AF_UNIX, SOCK_DGRAM,0)) < 0)
        return(OS_SOCKTERR);

    /* Making sure the path isn't there */
    unlink(path);
    
    if(bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0)
    {
        close(ossock);
        return(OS_SOCKTERR);
    }
    
    if(chmod(path,mode) < 0)
    {
        close(ossock);
        unlink(path);
        return(OS_FILERR);
    }
    
    return(ossock);
}

/* OS_ConnectUnixDomain v0.1, 2004/07/29
 * Open a client Unix domain socket
 * ("/tmp/lala-socket",0666));
 *
 */
int OS_ConnectUnixDomain(char * path)
{
    int ossock=0;

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

    /* Returning the socket */	
    return(ossock);
}


/* OS_Connect v 0.1, 2004/07/21
 * Open a TCP/UDP client socket 
 */
int OS_Connect(unsigned int _port, unsigned int protocol, char *_ip)
{
    int ossock;
    struct sockaddr_in server;

    if(protocol == IPPROTO_TCP){
        if((ossock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
            return(OS_SOCKTERR);
    }
    else if(protocol == IPPROTO_UDP){
        if((ossock = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
            return(OS_SOCKTERR);
    }
    else
        return(OS_INVALID);

    _cl = sizeof(server);	

    memset(&server, 0, _cl);
    server.sin_family = AF_INET;
    server.sin_port = htons( _port );

    if((_ip == NULL)||(_ip[0] == '\0'))
        return(OS_INVALID);        

    server.sin_addr.s_addr = inet_addr(_ip);

    if(connect(ossock,(struct sockaddr *)&server, _cl) < 0)
        return(OS_SOCKTERR);

    return(ossock);
}


/* OS_ConnectTCP, v0.1
 * Open a TCP socket
 */
int OS_ConnectTCP(unsigned int _port, char *_ip)
{
    return(OS_Connect(_port, IPPROTO_TCP,_ip));
}


/* OS_ConnectUDP, v0.1
 * Open a UDP socket 
 */
int OS_ConnectUDP(unsigned int _port, char *_ip)
{
    return(OS_Connect(_port, IPPROTO_UDP,_ip));
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
    if((send(socket,msg,size,0))<0)
        return(OS_SOCKTERR);
        
    return(0);
}


/* OS_AcceptTCP v0.1, 2005/01/28
 * Accept a TCP connection
 */
int OS_AcceptTCP(int socket,  char *srcip, int addrsize)
{
    int clientsocket;
    _cl = sizeof(_c);

    if((clientsocket = accept(socket, (struct sockaddr *) &_c,
                    &_cl)) < 0)
        return(-1);	

    strncpy(srcip, inet_ntoa(_c.sin_addr),addrsize -1);
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


/* OS_RecvUDP v 0.1, 2004/07/20
 * Receive a UDP packet
 */
char *OS_RecvUDP(int socket, int sizet)
{
    char *ret;
    
    ret = (char *) calloc((sizet), sizeof(char));
    if(ret == NULL)
        return(NULL);

    if((recvfrom(socket,ret,sizet-1,0,(struct sockaddr *)&_c,&_cl))<0)
        return(NULL);

    return(ret);
}

/* OS_RecvALLUDP v0.1, 2004/07/23
 * Duplicate work of the above function,
 * but returning also the source IP address
 */
char *OS_RecvAllUDP(int socket, int sizet, char *srcip, int addrsize)
{
    char *ret;
    
    ret = (char *) calloc((sizet), sizeof(char));
    
    if(ret == NULL)
        return(NULL);
    
    if((recvfrom(socket,ret,sizet-1,0,(struct sockaddr *)&_c,&_cl))<0)
        return(NULL);

    strncpy(srcip, inet_ntoa(_c.sin_addr),addrsize -1);
    srcip[addrsize -1]='\0';
    return(ret);
}

/* OS_RecvUnix, v0.1, 2004/07/29
 * Receive a message using a Unix socket
 */
char *OS_RecvUnix(int socket, int sizet)
{
    char *ret;
    socklen_t us_l;

    us_l = sizeof(n_us);

    ret = (char *) calloc((sizet), sizeof(char));
    
    if(ret == NULL)
        return(NULL);
    
    if(recvfrom(socket,ret,sizet-1,0,(struct sockaddr*)&n_us,&us_l) < 0)
        return(NULL);

    return(ret);
}

/* OS_SendUnix, v0.1, 2004/07/29
 * Send a message using a Unix socket
 */ 
int OS_SendUnix(int socket, char * msg, int size)
{
    int us_l;

    us_l = sizeof(n_us);
    
    if(size == 0)
        size = strlen(msg)+1;
        
    if(send(socket, msg, size,0) < size)
        return(OS_SOCKTERR);
        
    return(OS_SUCESS);
}

/* OS_GetHost, v0.1, 2005/01/181
 * Calls gethostbyname
 */
char *OS_GetHost(char *host)
{
    int sz;
    
    char *ip;
    struct hostent *h;
    extern int h_errno;

    if(host == NULL)
        return(NULL);
        
    if((h = gethostbyname(host)) == NULL)
        return(NULL);

    if(h_errno < 0 || h_errno > 2)
        return(NULL);

    sz = strlen(inet_ntoa(*((struct in_addr *)h->h_addr)))+1;
    if((ip = (char *) calloc(sz,sizeof(char))) == NULL)
        return(NULL);

    strncpy(ip,inet_ntoa(*((struct in_addr *)h->h_addr)),sz-1);
    
    return(ip);
}

/* EOF */

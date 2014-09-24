/* @(#) $Id: ./src/os_net/os_net.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_net Library.
 * APIs for many network operations.
 */

#include "headers/shared.h"
#ifdef WIN32
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG   0x0400
#endif
#ifndef AI_V4MAPPED
#define AI_V4MAPPED     0x0800
#endif
typedef unsigned short int sa_family_t;
#endif /* WIN32 */

#ifndef __OS_NET_H

#define __OS_NET_H


/* OS_Bindport*
 * Bind a specific port (protocol and a ip).
 * If the IP is not set, it is going to use ADDR_ANY
 * Return the socket.
 */
int OS_Bindporttcp(char *_port, const char *_ip);
int OS_Bindportudp(char *_port, const char *_ip);

/* OS_BindUnixDomain
 * Bind to a specific file, using the "mode" permissions in
 * a Unix Domain socket.
 */
int OS_BindUnixDomain(const char * path, mode_t mode, int max_msg_size) __attribute__((nonnull));
int OS_ConnectUnixDomain(const char * path, int max_msg_size) __attribute__((nonnull));
int OS_getsocketsize(int ossock);


/* OS_Connect
 * Connect to a TCP/UDP socket
 */
int OS_ConnectTCP(char *_port, const char *_ip);
int OS_ConnectUDP(char *_port, const char *_ip);

/* OS_RecvUDP
 * Receive a UDP packet. Return NULL if failed
 */
char *OS_RecvUDP(int socket, int sizet);
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size) __attribute__((nonnull));


/* OS_RecvUnix
 * Receive a message via a Unix socket
 */
int OS_RecvUnix(int socket, int sizet, char *ret) __attribute__((nonnull));


/* OS_RecvTCP
 * Receive a TCP packet
 */
int OS_AcceptTCP(int socket, char *srcip, size_t addrsize) __attribute__((nonnull));
char *OS_RecvTCP(int socket, int sizet);
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet) __attribute__((nonnull));


/* OS_SendTCP
 * Send a TCP/UDP/UnixSocket packet (in a open socket)
 */
int OS_SendTCP(int socket, const char *msg) __attribute__((nonnull));
int OS_SendTCPbySize(int socket, int size, const char *msg) __attribute__((nonnull));

int OS_SendUnix(int socket, const char * msg, int size) __attribute__((nonnull));

//int OS_SendUDP(int socket, char *msg);
int OS_SendUDPbySize(int socket, int size, const char *msg) __attribute__((nonnull));


/* OS_GetHost
 * Calls getaddrinfo
 */
char *OS_GetHost(const char *host, unsigned int attempts);


/* satop 
 * Convert a sockaddr to a printable address.
 */
int satop(struct sockaddr *sa, char *dst, socklen_t size);


/**
 * Close a network socket.
 * @param socket the socket to close
 * @return 0 on success, else -1 or SOCKET_ERROR
 */
int OS_CloseSocket(int socket);

#endif

/* EOF */

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

#ifndef __OS_NET_H

#define __OS_NET_H


/* OS_Bindport*
 * Bind a specific port (protocol and a ip).
 * If the IP is not set, it is going to use ADDR_ANY
 * Return the socket.
 */
int OS_Bindporttcp(char *_port, char *_ip);
int OS_Bindportudp(char *_port, char *_ip);

/* OS_BindUnixDomain
 * Bind to a specific file, using the "mode" permissions in
 * a Unix Domain socket.
 */
int OS_BindUnixDomain(char * path, int mode, int max_msg_size);
int OS_ConnectUnixDomain(char * path, int max_msg_size);
int OS_getsocketsize(int ossock);


/* OS_Connect
 * Connect to a TCP/UDP socket
 */
int OS_ConnectTCP(char *_port, char *_ip);
int OS_ConnectUDP(char *_port, char *_ip);

/* OS_RecvUDP
 * Receive a UDP packet. Return NULL if failed
 */
char *OS_RecvUDP(int socket, int sizet);
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size);


/* OS_RecvUnix
 * Receive a message via a Unix socket
 */
int OS_RecvUnix(int socket, int sizet, char *ret);


/* OS_RecvTCP
 * Receive a TCP packet
 */
int OS_AcceptTCP(int socket, char *srcip, int addrsize);
char *OS_RecvTCP(int socket, int sizet);
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet);


/* OS_SendTCP
 * Send a TCP/UDP/UnixSocket packet (in a open socket)
 */
int OS_SendTCP(int socket, char *msg);
int OS_SendTCPbySize(int socket, int size, char *msg);

int OS_SendUnix(int socket, char * msg, int size);

int OS_SendUDP(int socket, char *msg);
int OS_SendUDPbySize(int socket, int size, char *msg);


/* OS_GetHost
 * Calls getaddrinfo
 */
char *OS_GetHost(char *host, int attempts);


/* satop 
 * Convert a sockaddr to a printable address.
 */
int satop(struct sockaddr *sa, char *dst, socklen_t size);

#endif

/* EOF */

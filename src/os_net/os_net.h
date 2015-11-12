/* Copyright (C) 2009 Trend Micro Inc.
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

#ifndef __OS_NET_H
#define __OS_NET_H

/* OS_Bindport*
 * Bind a specific port (protocol and a ip).
 * If the IP is not set, it is going to use ADDR_ANY
 * Return the socket.
 */
int OS_Bindporttcp(u_int16_t _port, const char *_ip, int ipv6);
int OS_Bindportudp(u_int16_t _port, const char *_ip, int ipv6);

/* OS_BindUnixDomain
 * Bind to a specific file, using the "mode" permissions in
 * a Unix Domain socket.
 */
int OS_BindUnixDomain(const char *path, mode_t mode, int max_msg_size) __attribute__((nonnull));
int OS_ConnectUnixDomain(const char *path, int max_msg_size) __attribute__((nonnull));
int OS_getsocketsize(int ossock);

/* OS_Connect
 * Connect to a TCP/UDP socket
 */
int OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6, const char *_lip);
int OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6, const char *_lip);

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

int OS_SendUnix(int socket, const char *msg, int size) __attribute__((nonnull));

int OS_SendUDPbySize(int socket, int size, const char *msg) __attribute__((nonnull));

/* OS_GetHost
 * Calls gethostbyname
 */
char *OS_GetHost(const char *host, unsigned int attempts);

/* Close a network socket
 * Returns 0 on success, else -1 or SOCKET_ERROR
 */
int OS_CloseSocket(int socket);

#endif /* __OS_NET_H */


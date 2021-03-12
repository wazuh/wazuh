/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_net Library
 * APIs for many network operations
 */

#ifndef OS_NET_H
#define OS_NET_H

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
int OS_BindUnixDomain(const char *path, int type, int max_msg_size) __attribute__((nonnull));
int OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) __attribute__((nonnull));
int OS_getsocketsize(int ossock);

/* OS_Connect
 * Connect to a TCP/UDP socket
 */
int OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6);
int OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6);

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

/* Set the receiving timeout for a socket
 * Returns 0 on success, else -1
 */
int OS_SetRecvTimeout(int socket, long seconds, long useconds);

/*
 * Enable SO_KEEPALIVE for TCP
 */
int OS_SetKeepalive(int socket);

/**
 * @brief Set keepalive parameters for a socket
 *
 * Options with a value 0 will not be changed.
 *
 * @param socket Socket descriptor.
 * @param idle Idle time, in seconds, to start sending probes.
 * @param intvl Interval between probes, in seconds.
 * @param cnt Number of probes sent before closing the connection.
 */
void OS_SetKeepalive_Options(__attribute__((unused)) int socket, int idle, int intvl, int cnt);

/* Set the delivery timeout for a socket
 * Returns 0 on success, else -1
 */
int OS_SetSendTimeout(int socket, int seconds);

/**
 * @brief Send secure TCP message
 *
 * This function prepends a header containing message size as 4-byte little-endian unsigned integer.
 *
 * @param sock Socket file descriptor.
 * @param size Message length, in bytes.
 * @param msg Pointer to the message content.
 * @retval 0 on success.
 * @retval OS_SOCKTERR on error.
 */
int OS_SendSecureTCP(int sock, uint32_t size, const void * msg);

/* Receive secure TCP message
 * This function reads a header containing message size as 4-byte little-endian unsigned integer.
 * Return recvval on success or OS_SOCKTERR on error.
 */
int OS_RecvSecureTCP(int sock, char * ret,uint32_t size);

/**
 * @brief Send secure TCP Cluster message
 * @param sock Socket to write on
 * @param command Command to send
 * @param payload Payload of the command to send
 * @param length Length of the message to send
 * @return recvval on success
 * @return OS_SOCKTERR on error
 * */
int OS_SendSecureTCPCluster(int sock, const void * command, const void * payload, size_t length);

/**
 * @brief Receive secure TCP Cluster message
 * @param sock Socket to read from
 * @param ret Response read
 * @param length Max length to be read
 * @return recvval on success
 * @return -1 on socket errors
 * @return -2 on cluster errors
 * */
int OS_RecvSecureClusterTCP(int sock, char* ret, size_t length);

/* Byte ordering */
uint32_t wnet_order(uint32_t value);

/* Set the maximum buffer size for the socket */
int OS_SetSocketSize(int sock, int mode, int max_msg_size);

/* Receive a message from a stream socket, full message (MSG_WAITALL)
 * Returns size on success.
 * Returns -1 on socket error.
 * Returns 0 on socket disconnected or timeout.
 */
ssize_t os_recv_waitall(int sock, void * buf, size_t size);

// Wrapper for select()
int wnet_select(int sock, int timeout);

#endif /* OS_NET_H */

/*      $OSSEC, os_net.c, v0.2, 2004/08/02, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
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

#ifndef __OS_NET_H

#define __OS_NET_H

/* OS_Bindport*
 * Bind a specific port (protocol and a ip).
 * If the IP is not set, it is going to use ADDR_ANY
 * Return the socket.
 */
int OS_Bindporttcp(unsigned int _port, char *_ip);
int OS_Bindportudp(unsigned int _port, char *_ip);

/* OS_BindUnixDomain
 * Bind to a specific file, using the "mode" permissions in
 * a Unix Domain socket.
 */ 
int OS_BindUnixDomain(char * path, int mode);
int OS_ConnectUnixDomain(char * path); 

/* OS_Connect
 * Connect to a TCP/UDP socket
 */
int OS_ConnectTCP(unsigned int _port, char *_ip);
int OS_ConnectUDP(unsigned int _port, char *_ip);

/* OS_RecvUDP
 * Receive a UDP packet. Return NULL if failed
 */
char *OS_RecvUDP(int socket, int sizet);
char *OS_RecvAllUDP(int socket, int sizet, char *srcip, int addrsize);

/* OS_RecvUnix
 * Receive a message via a Unix socket
 */
char *OS_RecvUnix(int socket, int sizet);

/* OS_RecvTCP
 * Receive a TCP packet
 */
int OS_AcceptTCP(int socket, char *srcip, int addrsize);
char *OS_RecvTCP(int socket, int sizet);

/* OS_SendTCP 
 * Send a TCP/UDP/UnixSocket packet (in a open socket)
 */
int OS_SendTCP(int socket, char *msg);
int OS_SendTCPbySize(int socket, int size, char *msg);

int OS_SendUnix(int socket, char * msg, int size);

int OS_SendUDP(int socket, char *msg);
int OS_SendUDPbySize(int socket, int size, char *msg);

/* OS_GetHost
 * Calls gethostbyname
 */
char *OS_GetHost(char *host);

#endif

/* EOF */

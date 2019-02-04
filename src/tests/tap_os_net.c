#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <defs.h>

#include "shared.h"
#include "os_net/os_net.h"
#include "os_err.h"

#include "tap.h"

#define IPV4 "127.0.0.1"
#define IPV6 "::1"
#define PORT 4321
#define SENDSTRING "Hello World!\n"
#define BUFFERSIZE 1024

int test_tcpv4_local() {
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];


    if ((server_root_socket = OS_Bindporttcp(PORT, IPV4, 0)), server_root_socket < 0){
        return 0;
    }
    
    if ((client_socket = OS_ConnectTCP(PORT, IPV4, 0)), client_socket < 0){
        return 0;
    }

    if ((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), server_client_socket < 0){
        return 0;
    }

    if (strcmp(ipbuffer, IPV4) != 0){
        return 0;
    }

    if (OS_SendTCP(client_socket, SENDSTRING) != 0){
        return 0;
    }

    if (OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE) != 0){
        return 0;
    }
    
    if (strcmp(buffer, SENDSTRING) != 0){
        return 0;
    }

    if (OS_SendTCPbySize(server_client_socket, 5, SENDSTRING) != 0){
        return 0;
    }

    if(msg = OS_RecvTCP(client_socket, BUFFERSIZE), msg == NULL){
        return 0;
    }

    if (strcmp(msg, "Hello") != 0){
        return 0;
    }

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
    return 1;
}


int test_tcpv4_inet() {
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];


    if ((server_root_socket = OS_Bindporttcp(PORT, NULL, 0)), server_root_socket < 0){
        return 0;
    }
    
    if ((client_socket = OS_ConnectTCP(PORT, IPV4, 0)), client_socket < 0){
        return 0;
    }

    if ((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), server_client_socket < 0){
        return 0;
    }

    if (strcmp(ipbuffer, IPV4) != 0){
        return 0;
    }

    if (OS_SendTCP(client_socket, SENDSTRING) != 0){
        return 0;
    }

    if (OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE) != 0){
        return 0;
    }
    
    if (strcmp(buffer, SENDSTRING) != 0){
        return 0;
    }

    if (OS_SendTCPbySize(server_client_socket, 5, SENDSTRING) != 0){
        return 0;
    }

    if(msg = OS_RecvTCP(client_socket, BUFFERSIZE), msg == NULL){
        return 0;
    }

    if (strcmp(msg, "Hello") != 0){
        return 0;
    }

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
    return 1;
}

int test_tcpv6() {
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    if ((server_root_socket = OS_Bindporttcp(PORT, IPV6, 1)), server_root_socket < 0){
        return 0;
    }

    if ((client_socket = OS_ConnectTCP(PORT, IPV6, 1)), client_socket < 0){
        return 0;
    }

    if ((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), server_client_socket < 0){
        return 0;
    }
    
    if (strcmp(ipbuffer, "0.0.0.0") != 0){
        return 0;
    }

    if (OS_SendTCP(client_socket, SENDSTRING) != 0){
        return 0;
    }

    if (OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE) != 0){
        return 0;
    }
    
    if (strcmp(buffer, SENDSTRING) != 0){
        return 0;
    }

    if (OS_SendTCPbySize(server_client_socket, 5, SENDSTRING) != 0){
        return 0;
    }

    if(msg = OS_RecvTCP(client_socket, BUFFERSIZE), msg == NULL){
        return 0;
    }

    if (strcmp(msg, "Hello") != 0){
        return 0;
    }

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
    return 1;
}

int test_tcp_invalid_sockets() {
    char buffer[BUFFERSIZE];

    if (OS_SendTCP(-1, SENDSTRING) != OS_SOCKTERR){
        return 1;
    }

    if (OS_SendTCPbySize(-1, strlen(SENDSTRING), SENDSTRING) != OS_SOCKTERR){
        return 1;
    }

    if (OS_RecvTCP(-1, BUFFERSIZE) != NULL){
        return 1;
    }

    if (OS_RecvTCPBuffer(-1, buffer, BUFFERSIZE) != -1){
        return 1;
    }

    if (OS_AcceptTCP(-1, buffer, BUFFERSIZE) != -1){
        return 1;
    }

    return 0;
}

int test_udpv4() {
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    if ((server_socket = OS_Bindportudp(PORT, IPV4, 0)), server_socket < 0){
        return 0;
    }
    
    if ((client_socket = OS_ConnectUDP(PORT, IPV4, 0)), client_socket < 0){
        return 0;
    }

    if(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING) != 0){
        return 0;
    }

    if(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE) != strlen(SENDSTRING)){
        return 0;
    }

    if (strcmp(buffer, SENDSTRING) != 0){
        return 0;
    }

    if (OS_SendUDPbySize(client_socket, 5, SENDSTRING) != 0){
        return 0;
    }

    if(msg = OS_RecvUDP(server_socket, BUFFERSIZE), msg == NULL){
        return 0;
    }

    if (strcmp(msg, "Hello") != 0){
        return 0;
    }

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    return 1;
}

int test_udpv6() {
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    if ((server_socket = OS_Bindportudp(PORT, IPV6, 1)), server_socket < 0){
        return 0;
    }
    
    if ((client_socket = OS_ConnectUDP(PORT, IPV6, 1)), client_socket < 0){
        return 0;
    }

    if(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING) != 0){
        return 0;
    }

    if(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE) != strlen(SENDSTRING)){
        return 0;
    }

    if (strcmp(buffer, SENDSTRING) != 0){
        return 0;
    }

    if (OS_SendUDPbySize(client_socket, 5, SENDSTRING) != 0){
        return 0;
    }

    if(msg = OS_RecvUDP(server_socket, BUFFERSIZE), msg == NULL){
        return 0;
    }

    if (strcmp(msg, "Hello") != 0){
        return 0;
    }

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    return 1;
}

int test_udp_invalid_sockets() {
    char buffer[BUFFERSIZE];

    if (OS_SendUDPbySize(-1, strlen(SENDSTRING), SENDSTRING) != OS_SOCKTERR){
        return 1;
    }

    if (OS_RecvUDP(-1, BUFFERSIZE) != NULL){
        return 1;
    }

    if (OS_RecvConnUDP(-1, buffer, BUFFERSIZE) != 0){
        return 1;
    }

    return 0;
}

int test_unix() {
    int fd;

    /* create socket path */
    char socket_path[256];
    strncpy(socket_path, "/tmp/tmp_file-XXXXXX", 256);
    fd = mkstemp(socket_path);
    close(fd);

    int server_socket, client_socket;
    const int msg_size = 2048;
    char buffer[BUFFERSIZE];

    if ((server_socket = OS_BindUnixDomain(socket_path, SOCK_DGRAM, msg_size)), server_socket < 0){
        return 0;
    }

    if (OS_getsocketsize(server_socket) < msg_size){
        return 0;
    }

    if ((client_socket = OS_ConnectUnixDomain(socket_path, SOCK_DGRAM, msg_size)), client_socket < 0){
        return 0;
    }

    if(OS_SendUnix(client_socket, SENDSTRING, 5) != 0){
        return 0;
    }

    if(OS_RecvUnix(server_socket, BUFFERSIZE, buffer) != 5){
        return 0;
    }

    if (strcmp(buffer, "Hello") != 0){
        return 0;
    }

    if(OS_SendUnix(client_socket, SENDSTRING, 0) != 0){
        return 0;
    }

    if(OS_RecvUnix(server_socket, BUFFERSIZE, buffer) != strlen(SENDSTRING) + 1){
        return 0;
    }

    if (strcmp(buffer, SENDSTRING) != 0){
        return 0;
    }

    return 1;
}

int test_unix_invalid_sockets() {
    char buffer[BUFFERSIZE];

    if(OS_SendUnix(-1, SENDSTRING, strlen(SENDSTRING)) != OS_SOCKTERR){
        return 1;
    }

    if(OS_RecvUnix(-1, BUFFERSIZE, buffer) != 0){
        return 1;
    }

    return 0;
}

int test_gethost_success() {
    char *ret;

    if(ret = OS_GetHost("google-public-dns-a.google.com", 2), ret == NULL){
        return 0;
    }

    if(strcmp(ret,"8.8.8.8") != 0){
        return 0;
    }
    
    free(ret);
    
    return 1;
}

int test_gethost_null() {

    if(!OS_GetHost(NULL, 2)){
        return 0;
    }

    return 1;
}

int test_gethost_not_exists() {

    if(!OS_GetHost("this.should.not.exist", 2)){
        return 0;
    }

    return 1;
}

int main(void) {
    printf(CYELLOW"\n\n    STARTING TEST - OS_NET   \n\n" CEND);

    // Send and receive string using TCP IPV4 socket on localhost
    TAP_TEST_MSG(test_tcpv4_local(), "TCP IPV4 send an receive: localhost test.");

    // Send and receive string using TCP IPV4 socket on inet
    TAP_TEST_MSG(test_tcpv4_local(), "TCP IPV4 send an receive: inet test.");

    // Send and receive string using TCP IPV4 socket on inet
    TAP_TEST_MSG(test_tcpv6(), "TCP IPV6 send an receive test.");

    // Try to use invalid TCP sockets
    TODO;    
    TAP_TEST_MSG(test_tcp_invalid_sockets(), "TCP invalid socket test.");
    END_TODO;

    // Send and receive string using UDP IPV4 socket on inet
    TAP_TEST_MSG(test_udpv4(), "UDP IPV4 send an receive test.");

    // Send and receive string using UDP IPV6 socket on inet
    TAP_TEST_MSG(test_udpv6(), "UDP IPV6 send an receive test.");

    // Try to use invalid UDP sockets
    TODO;
    TAP_TEST_MSG(test_udp_invalid_sockets(), "UDP invalid socket test.");
    END_TODO;

    // Send and receive string using Unix sockets
    TAP_TEST_MSG(test_unix(), "Unix sockets test.");

    // Try to use invalid Unix sockets
    TODO;
    TAP_TEST_MSG(test_unix_invalid_sockets(), "Unix invalid socket test.");
    END_TODO;

    // Try to get host by name
    TAP_TEST_MSG(test_gethost_success(), "Get host by name: google dns test.");

    // Try to get host by name with null host name
    TODO;
    TAP_TEST_MSG(test_gethost_null(), "Get host by name: null host test.");
    END_TODO;

    // Try to get host by name with non-existent host name
    TODO;    
    TAP_TEST_MSG(test_gethost_not_exists(), "Get host by name: non-existent host test.");
    END_TODO;

    TAP_PLAN;
    TAP_SUMMARY;
    printf(CYELLOW "\n    ENDING TEST  - OS_NET   \n\n" CEND);
    return 0;
}
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

    w_assert_int_ge((server_root_socket = OS_Bindporttcp(PORT, IPV4, 0)), 0);

    w_assert_int_ge((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    w_assert_int_ge((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    w_assert_str_eq(ipbuffer, IPV4);

    w_assert_int_eq(OS_SendTCP(client_socket, SENDSTRING), 0);

    w_assert_int_eq(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 0);

    w_assert_str_eq(buffer, SENDSTRING);

    w_assert_int_eq(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    w_assert_ptr_ne((msg = OS_RecvTCP(client_socket, BUFFERSIZE)), NULL);

    w_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

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

    w_assert_int_ge((server_root_socket = OS_Bindporttcp(PORT, NULL, 0)), 0);

    w_assert_int_ge((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    w_assert_int_ge((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    w_assert_str_eq(ipbuffer, IPV4);

    w_assert_int_eq(OS_SendTCP(client_socket, SENDSTRING), 0);

    w_assert_int_eq(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 0);

    w_assert_str_eq(buffer, SENDSTRING);

    w_assert_int_eq(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    w_assert_ptr_ne((msg = OS_RecvTCP(client_socket, BUFFERSIZE)), NULL);

    w_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

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

    w_assert_int_ge((server_root_socket = OS_Bindporttcp(PORT, IPV6, 1)), 0);

    w_assert_int_ge((client_socket = OS_ConnectTCP(PORT, IPV6, 1)) , 0);

    w_assert_int_ge((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    //TODO: ipv6 ip
    w_assert_str_eq(ipbuffer, "0.0.0.0");

    w_assert_int_eq(OS_SendTCP(client_socket, SENDSTRING), 0);

    w_assert_int_eq(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 0);

    w_assert_str_eq(buffer, SENDSTRING);

    w_assert_int_eq(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    w_assert_ptr_ne((msg = OS_RecvTCP(client_socket, BUFFERSIZE)), NULL);

    w_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
    return 1;
}

int test_tcp_invalid_sockets() {
    char buffer[BUFFERSIZE];

    w_assert_int_eq(OS_SendTCP(-1, SENDSTRING), OS_SOCKTERR);

    w_assert_int_eq(OS_SendTCPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);

    w_assert_ptr_eq(OS_RecvTCP(-1, BUFFERSIZE), NULL);

    w_assert_int_eq(OS_RecvTCPBuffer(-1, buffer, BUFFERSIZE), -1);

    w_assert_int_eq(OS_AcceptTCP(-1, buffer, BUFFERSIZE), -1);

    return 1;
}

int test_udpv4() {
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    w_assert_int_ge((server_socket = OS_Bindportudp(PORT, IPV4, 0)), 0);

    w_assert_int_ge((client_socket = OS_ConnectUDP(PORT, IPV4, 0)) , 0);

    //TODO: w_assert_int_eq(OS_SendUDP(client_socket, SENDSTRING), 0);
    w_assert_int_eq(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    //TODO: not null-terminated
    w_assert_int_eq(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));

    w_assert_str_eq(buffer, SENDSTRING);

    w_assert_int_eq(OS_SendUDPbySize(client_socket, 5, SENDSTRING), 0);

    w_assert_ptr_ne((msg = OS_RecvUDP(server_socket, BUFFERSIZE)), NULL);

    w_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    return 1;
}

int test_udpv6() {
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    w_assert_int_ge((server_socket = OS_Bindportudp(PORT, IPV6, 1)), 0);

    w_assert_int_ge((client_socket = OS_ConnectUDP(PORT, IPV6, 1)) , 0);

    //TODO: w_assert_int_eq(OS_SendUDP(client_socket, SENDSTRING), 0);
    w_assert_int_eq(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    //TODO: not null-terminated
    w_assert_int_eq(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));

    w_assert_str_eq(buffer, SENDSTRING);

    w_assert_int_eq(OS_SendUDPbySize(client_socket, 5, SENDSTRING), 0);

    w_assert_ptr_ne((msg = OS_RecvUDP(server_socket, BUFFERSIZE)), NULL);

    w_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    return 1;
}

int test_udp_invalid_sockets() {
    char buffer[BUFFERSIZE];

    w_assert_int_eq(OS_SendUDPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);

    w_assert_ptr_eq(OS_RecvUDP(-1, BUFFERSIZE), NULL);

    w_assert_int_eq(OS_RecvConnUDP(-1, buffer, BUFFERSIZE), 0);

    return 1;
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

    w_assert_int_ge((server_socket = OS_BindUnixDomain(socket_path, SOCK_DGRAM, msg_size)), 0);

    w_assert_int_ge(OS_getsocketsize(server_socket), msg_size);

    w_assert_int_ge((client_socket = OS_ConnectUnixDomain(socket_path, SOCK_DGRAM, msg_size)), 0);

    w_assert_int_eq(OS_SendUnix(client_socket, SENDSTRING, 5), 0);

    w_assert_int_eq(OS_RecvUnix(server_socket, BUFFERSIZE, buffer), 5);

    w_assert_str_eq(buffer, "Hello");

    w_assert_int_eq(OS_SendUnix(client_socket, SENDSTRING, 0), 0);

    w_assert_int_eq(OS_RecvUnix(server_socket, BUFFERSIZE, buffer), strlen(SENDSTRING) + 1);

    w_assert_str_eq(buffer, SENDSTRING);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    unlink(socket_path);

    return 1;
}

int test_unix_invalid_sockets() {
    char buffer[BUFFERSIZE];

    w_assert_int_eq(OS_SendUnix(-1, SENDSTRING, strlen(SENDSTRING)), OS_SOCKTERR);

    w_assert_int_eq(OS_RecvUnix(-1, BUFFERSIZE, buffer), 0);

    return 1;
}

int test_gethost_success() {
    char *ret;

    w_assert_ptr_ne((ret = OS_GetHost("google-public-dns-a.google.com", 2)), NULL);
    w_assert_str_eq(ret, "8.8.8.8");

    free(ret);

    return 1;
}

int test_gethost_null() {
    w_assert_ptr_eq(OS_GetHost(NULL, 2), NULL);
    return 1;
}

int test_gethost_not_exists() {
    w_assert_ptr_eq(OS_GetHost("this.should.not.exist", 2), NULL);
    return 1;
}

int main(void) {
    printf("\n\n    STARTING TEST - OS_NET   \n\n");

    // Send and receive string using TCP IPV4 socket on localhost
    TAP_TEST_MSG(test_tcpv4_local(), "TCP IPV4 send an receive: localhost test.");

    // Send and receive string using TCP IPV4 socket on inet
    TAP_TEST_MSG(test_tcpv4_local(), "TCP IPV4 send an receive: inet test.");

    // Send and receive string using TCP IPV4 socket on inet
    TAP_TEST_MSG(test_tcpv6(), "TCP IPV6 send an receive test.");

    // Try to use invalid TCP sockets
    TAP_TEST_MSG(test_tcp_invalid_sockets(), "TCP invalid socket test.");

    // Send and receive string using UDP IPV4 socket on inet
    TAP_TEST_MSG(test_udpv4(), "UDP IPV4 send an receive test.");

    // Send and receive string using UDP IPV6 socket on inet
    TAP_TEST_MSG(test_udpv6(), "UDP IPV6 send an receive test.");

    // Try to use invalid UDP sockets
    TAP_TEST_MSG(test_udp_invalid_sockets(), "UDP invalid socket test.");

    // Send and receive string using Unix sockets
    TAP_TEST_MSG(test_unix(), "Unix sockets test.");

    // Try to use invalid Unix sockets
    TAP_TEST_MSG(test_unix_invalid_sockets(), "Unix invalid socket test.");

    // Try to get host by name
    TAP_TEST_MSG(test_gethost_success(), "Get host by name: google dns test.");

    // Try to get host by name with null host name
    TAP_TEST_MSG(test_gethost_null(), "Get host by name: null host test.");

    // Try to get host by name with non-existent host name
    TAP_TEST_MSG(test_gethost_not_exists(), "Get host by name: non-existent host test.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n    ENDING TEST  - OS_NET   \n\n");
    return 0;
}
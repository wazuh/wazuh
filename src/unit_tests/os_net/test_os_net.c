/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "os_err.h"
#include "sym_load.h"
#include "../../data_provider/include/sysInfo.h"
#include "../../headers/shared.h"
#include "../../os_net/os_net.h"
#include "../wrappers/common.h"

#define IPV4 "127.0.0.1"
#define IPV6 "::1"
#define PORT 4321
#define SENDSTRING "Hello World!\n"
#define BUFFERSIZE 1024

extern sysinfo_networks_func sysinfo_network_ptr;
extern sysinfo_free_result_func sysinfo_free_result_ptr;
void *test_sysinfo_module = NULL;

// Tests

void test_tcpv4_local(void **state)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    assert_return_code((server_root_socket = OS_Bindporttcp(PORT, IPV4, 0)), 0);

    assert_return_code((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    assert_return_code((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    assert_string_equal(ipbuffer, IPV4);

    assert_int_equal(OS_SendTCP(client_socket, SENDSTRING), 0);

    assert_int_equal(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 13);

    assert_string_equal(buffer, SENDSTRING);

    assert_int_equal(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    assert_non_null((msg = OS_RecvTCP(client_socket, BUFFERSIZE)));

    assert_string_equal(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}

void test_tcpv4_inet(void **state)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    assert_return_code((server_root_socket = OS_Bindporttcp(PORT, NULL, 0)), 0);

    assert_return_code((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    assert_return_code((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    assert_string_equal(ipbuffer, IPV4);

    assert_int_equal(OS_SendTCP(client_socket, SENDSTRING), 0);

    assert_int_equal(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 13);

    assert_string_equal(buffer, SENDSTRING);

    assert_int_equal(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    assert_non_null((msg = OS_RecvTCP(client_socket, BUFFERSIZE)));

    assert_string_equal(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}

void test_tcpv4_secure(void **state)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char ipbuffer[BUFFERSIZE];

    assert_return_code((server_root_socket = OS_Bindporttcp(PORT, IPV4, 0)), 0);

    assert_return_code((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    assert_return_code((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    assert_string_equal(ipbuffer, IPV4);

    assert_int_equal(OS_SendSecureTCP(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    assert_int_equal(OS_RecvSecureTCP(server_client_socket, buffer, BUFFERSIZE), 13);

    assert_string_equal(buffer, SENDSTRING);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}

void test_tcpv6(void **state)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    assert_return_code((server_root_socket = OS_Bindporttcp(PORT, IPV6, 1)), 0);

    assert_return_code((client_socket = OS_ConnectTCP(PORT, IPV6, 1)) , 0);

    assert_return_code((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    assert_string_equal(ipbuffer, "0.0.0.0");

    assert_int_equal(OS_SendTCP(client_socket, SENDSTRING), 0);

    assert_int_equal(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 13);

    assert_string_equal(buffer, SENDSTRING);

    assert_int_equal(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    assert_non_null((msg = OS_RecvTCP(client_socket, BUFFERSIZE)));

    assert_string_equal(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}

void test_tcpv6_secure(void **state)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char ipbuffer[BUFFERSIZE];

    assert_return_code((server_root_socket = OS_Bindporttcp(PORT, IPV6, 1)), 0);

    assert_return_code((client_socket = OS_ConnectTCP(PORT, IPV6, 1)) , 0);

    assert_return_code((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    assert_string_equal(ipbuffer, "0.0.0.0");

    assert_int_equal(OS_SendSecureTCP(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    assert_int_equal(OS_RecvSecureTCP(server_client_socket, buffer, BUFFERSIZE), 13);

    assert_string_equal(buffer, SENDSTRING);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}

void test_tcp_invalid_sockets(void **state)
{
    char buffer[BUFFERSIZE];

    assert_int_equal(OS_SendTCP(-1, SENDSTRING), OS_SOCKTERR);

    assert_int_equal(OS_SendTCPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);

    assert_null(OS_RecvTCP(-1, BUFFERSIZE));

    assert_int_equal(OS_RecvTCPBuffer(-1, buffer, BUFFERSIZE), -1);

    assert_int_equal(OS_AcceptTCP(-1, buffer, BUFFERSIZE), -1);
}

void test_udpv4(void **state)
{
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    assert_return_code((server_socket = OS_Bindportudp(PORT, IPV4, 0)), 0);

    assert_return_code((client_socket = OS_ConnectUDP(PORT, IPV4, 0)) , 0);

    assert_int_equal(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    assert_int_equal(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));

    assert_string_equal(buffer, SENDSTRING);

    assert_int_equal(OS_SendUDPbySize(client_socket, 5, SENDSTRING), 0);

    assert_non_null((msg = OS_RecvUDP(server_socket, BUFFERSIZE)));

    assert_string_equal(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);
}

void test_udpv6(void **state)
{
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    assert_return_code((server_socket = OS_Bindportudp(PORT, IPV6, 1)), 0);

    assert_return_code((client_socket = OS_ConnectUDP(PORT, IPV6, 1)) , 0);

    assert_int_equal(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    assert_int_equal(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));

    assert_string_equal(buffer, SENDSTRING);

    assert_int_equal(OS_SendUDPbySize(client_socket, 5, SENDSTRING), 0);

    assert_non_null((msg = OS_RecvUDP(server_socket, BUFFERSIZE)));

    assert_string_equal(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);
}

void test_udp_invalid_sockets(void **state)
{
    char buffer[BUFFERSIZE];

    assert_int_equal(OS_SendUDPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);

    assert_null(OS_RecvUDP(-1, BUFFERSIZE));

    assert_int_equal(OS_RecvConnUDP(-1, buffer, BUFFERSIZE), 0);
}

void test_unix(void **state)
{
    int fd;

    /* create socket path */
    char socket_path[256];
    strncpy(socket_path, "/tmp/tmp_file-XXXXXX", 256);
    fd = mkstemp(socket_path);
    close(fd);

    int server_socket, client_socket;
    const int msg_size = 2048;
    char buffer[BUFFERSIZE];

    assert_return_code((server_socket = OS_BindUnixDomain(socket_path, SOCK_DGRAM, msg_size)), 0);

    assert_return_code(OS_getsocketsize(server_socket), msg_size);

    assert_return_code((client_socket = OS_ConnectUnixDomain(socket_path, SOCK_DGRAM, msg_size)), 0);

    assert_int_equal(OS_SendUnix(client_socket, SENDSTRING, 5), 0);

    assert_int_equal(OS_RecvUnix(server_socket, BUFFERSIZE - 1, buffer), 5);

    assert_string_equal(buffer, "Hello");

    assert_int_equal(OS_SendUnix(client_socket, SENDSTRING, 0), 0);

    assert_int_equal(OS_RecvUnix(server_socket, BUFFERSIZE - 1, buffer), strlen(SENDSTRING) + 1);

    assert_string_equal(buffer, SENDSTRING);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    unlink(socket_path);
}

void test_unix_invalid_sockets(void **state)
{
    char buffer[BUFFERSIZE];

    assert_int_equal(OS_SendUnix(-1, SENDSTRING, strlen(SENDSTRING)), OS_SOCKTERR);

    assert_int_equal(OS_RecvUnix(-1, BUFFERSIZE - 1, buffer), 0);
}

void test_gethost_success(void **state)
{
    char *ret;

    assert_non_null((ret = OS_GetHost("google-public-dns-a.google.com", 2)));
    assert_string_equal(ret, "8.8.8.8");

    free(ret);
}

void test_gethost_null(void **state)
{
    assert_null(OS_GetHost(NULL, 2));
}

void test_gethost_not_exists(void **state)
{
    assert_null(OS_GetHost("this.should.not.exist", 2));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tcpv4_local),
        cmocka_unit_test(test_tcpv4_inet),
        cmocka_unit_test(test_tcpv4_secure),
        cmocka_unit_test(test_tcpv6),
        cmocka_unit_test(test_tcpv6_secure),
        cmocka_unit_test(test_tcp_invalid_sockets),
        cmocka_unit_test(test_udpv4),
        cmocka_unit_test(test_udpv6),
        cmocka_unit_test(test_udp_invalid_sockets),
        cmocka_unit_test(test_unix),
        cmocka_unit_test(test_unix_invalid_sockets),
        cmocka_unit_test(test_gethost_success),
        cmocka_unit_test(test_gethost_null),
        cmocka_unit_test(test_gethost_not_exists),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <check.h>
#include <stdlib.h>
#include <unistd.h>

#include "shared.h"
#include "os_net/os_net.h"
#include "os_err.h"

#define IPV4 "127.0.0.1"
#define IPV6 "::1"
#define PORT 4321
#define SENDSTRING "Hello World!\n"
#define BUFFERSIZE 1024

Suite *test_suite(void);


START_TEST(test_tcpv4_local)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    ck_assert_int_ge((server_root_socket = OS_Bindporttcp(PORT, IPV4, 0)), 0);

    ck_assert_int_ge((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    ck_assert_int_ge((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    ck_assert_str_eq(ipbuffer, IPV4);

    ck_assert_int_eq(OS_SendTCP(client_socket, SENDSTRING), 0);

    ck_assert_int_eq(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 0);

    ck_assert_str_eq(buffer, SENDSTRING);

    ck_assert_int_eq(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    ck_assert_ptr_ne((msg = OS_RecvTCP(client_socket, BUFFERSIZE)), NULL);

    ck_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}
END_TEST

START_TEST(test_tcpv4_inet)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    ck_assert_int_ge((server_root_socket = OS_Bindporttcp(PORT, NULL, 0)), 0);

    ck_assert_int_ge((client_socket = OS_ConnectTCP(PORT, IPV4, 0)) , 0);

    ck_assert_int_ge((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    ck_assert_str_eq(ipbuffer, IPV4);

    ck_assert_int_eq(OS_SendTCP(client_socket, SENDSTRING), 0);

    ck_assert_int_eq(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 0);

    ck_assert_str_eq(buffer, SENDSTRING);

    ck_assert_int_eq(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    ck_assert_ptr_ne((msg = OS_RecvTCP(client_socket, BUFFERSIZE)), NULL);

    ck_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}
END_TEST

START_TEST(test_tcpv6)
{
    int server_root_socket, server_client_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;
    char ipbuffer[BUFFERSIZE];

    ck_assert_int_ge((server_root_socket = OS_Bindporttcp(PORT, IPV6, 1)), 0);

    ck_assert_int_ge((client_socket = OS_ConnectTCP(PORT, IPV6, 1)) , 0);

    ck_assert_int_ge((server_client_socket = OS_AcceptTCP(server_root_socket, ipbuffer, BUFFERSIZE)), 0);

    //TODO: ipv6 ip
    ck_assert_str_eq(ipbuffer, "0.0.0.0");

    ck_assert_int_eq(OS_SendTCP(client_socket, SENDSTRING), 0);

    ck_assert_int_eq(OS_RecvTCPBuffer(server_client_socket, buffer, BUFFERSIZE), 0);

    ck_assert_str_eq(buffer, SENDSTRING);

    ck_assert_int_eq(OS_SendTCPbySize(server_client_socket, 5, SENDSTRING), 0);

    ck_assert_ptr_ne((msg = OS_RecvTCP(client_socket, BUFFERSIZE)), NULL);

    ck_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_client_socket);
    OS_CloseSocket(server_root_socket);
}
END_TEST

START_TEST(test_tcpinvalidsockets)
{
    char buffer[BUFFERSIZE];

    ck_assert_int_eq(OS_SendTCP(-1, SENDSTRING), OS_SOCKTERR);

    ck_assert_int_eq(OS_SendTCPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);

    ck_assert_ptr_eq(OS_RecvTCP(-1, BUFFERSIZE), NULL);

    ck_assert_int_eq(OS_RecvTCPBuffer(-1, buffer, BUFFERSIZE), -1);

    ck_assert_int_eq(OS_AcceptTCP(-1, buffer, BUFFERSIZE), -1);
}
END_TEST

START_TEST(test_udpv4)
{
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    ck_assert_int_ge((server_socket = OS_Bindportudp(PORT, IPV4, 0)), 0);

    ck_assert_int_ge((client_socket = OS_ConnectUDP(PORT, IPV4, 0)) , 0);

    //TODO: ck_assert_int_eq(OS_SendUDP(client_socket, SENDSTRING), 0);
    ck_assert_int_eq(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    //TODO: not null-terminated
    ck_assert_int_eq(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));

    ck_assert_str_eq(buffer, SENDSTRING);

    ck_assert_int_eq(OS_SendUDPbySize(client_socket, 5, SENDSTRING), 0);

    ck_assert_ptr_ne((msg = OS_RecvUDP(server_socket, BUFFERSIZE)), NULL);

    ck_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);
}
END_TEST

START_TEST(test_udpv6)
{
    int server_socket, client_socket;
    char buffer[BUFFERSIZE];
    char *msg;

    ck_assert_int_ge((server_socket = OS_Bindportudp(PORT, IPV6, 1)), 0);

    ck_assert_int_ge((client_socket = OS_ConnectUDP(PORT, IPV6, 1)) , 0);

    //TODO: ck_assert_int_eq(OS_SendUDP(client_socket, SENDSTRING), 0);
    ck_assert_int_eq(OS_SendUDPbySize(client_socket, strlen(SENDSTRING), SENDSTRING), 0);

    //TODO: not null-terminated
    ck_assert_int_eq(OS_RecvConnUDP(server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));

    ck_assert_str_eq(buffer, SENDSTRING);

    ck_assert_int_eq(OS_SendUDPbySize(client_socket, 5, SENDSTRING), 0);

    ck_assert_ptr_ne((msg = OS_RecvUDP(server_socket, BUFFERSIZE)), NULL);

    ck_assert_str_eq(msg, "Hello"); /* only 5 bytes send */

    free(msg);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);
}
END_TEST

START_TEST(test_udpinvalidsockets)
{
    char buffer[BUFFERSIZE];

    //TODO: ck_assert_int_eq(OS_SendUDP(-1, SENDSTRING), OS_SOCKTERR);

    ck_assert_int_eq(OS_SendUDPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);

    ck_assert_ptr_eq(OS_RecvUDP(-1, BUFFERSIZE), NULL);

    ck_assert_int_eq(OS_RecvConnUDP(-1, buffer, BUFFERSIZE), 0);
}
END_TEST

START_TEST(test_unix)
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

    ck_assert_int_ge((server_socket = OS_BindUnixDomain(socket_path, SOCK_DGRAM, msg_size)), 0);

    ck_assert_int_ge(OS_getsocketsize(server_socket), msg_size);

    ck_assert_int_ge((client_socket = OS_ConnectUnixDomain(socket_path, SOCK_DGRAM, msg_size)), 0);

    ck_assert_int_eq(OS_SendUnix(client_socket, SENDSTRING, 5), 0);

    ck_assert_int_eq(OS_RecvUnix(server_socket, BUFFERSIZE, buffer), 5);

    ck_assert_str_eq(buffer, "Hello");

    ck_assert_int_eq(OS_SendUnix(client_socket, SENDSTRING, 0), 0);

    ck_assert_int_eq(OS_RecvUnix(server_socket, BUFFERSIZE, buffer), strlen(SENDSTRING) + 1);

    ck_assert_str_eq(buffer, SENDSTRING);

    OS_CloseSocket(client_socket);
    OS_CloseSocket(server_socket);

    unlink(socket_path);
}
END_TEST

START_TEST(test_unixinvalidsockets)
{
    char buffer[BUFFERSIZE];

    ck_assert_int_eq(OS_SendUnix(-1, SENDSTRING, strlen(SENDSTRING)), OS_SOCKTERR);

    ck_assert_int_eq(OS_RecvUnix(-1, BUFFERSIZE, buffer), 0);
}
END_TEST

START_TEST(test_gethost_success)
{
    char *ret;

    ck_assert_ptr_ne((ret = OS_GetHost("google-public-dns-a.google.com", 2)), NULL);
    ck_assert_str_eq(ret, "8.8.8.8");

    free(ret);
}
END_TEST

START_TEST(test_gethost_fail1)
{
    ck_assert_ptr_eq(OS_GetHost(NULL, 2), NULL);
}
END_TEST

START_TEST(test_gethost_fail2)
{
    ck_assert_ptr_eq(OS_GetHost("this.should.not.exist", 2), NULL);
}
END_TEST


Suite *test_suite(void)
{
    Suite *s = suite_create("os_net");

    TCase *tc_tcp = tcase_create("TCP");
    tcase_add_test(tc_tcp, test_tcpv4_local);
    tcase_add_test(tc_tcp, test_tcpv4_inet);
    tcase_add_test(tc_tcp, test_tcpv6);
    tcase_add_test(tc_tcp, test_tcpinvalidsockets);

    TCase *tc_udp = tcase_create("UDP");
    tcase_add_test(tc_udp, test_udpv4);
    tcase_add_test(tc_udp, test_udpv6);
    tcase_add_test(tc_udp, test_udpinvalidsockets);

    TCase *tc_unix = tcase_create("Unix");
    tcase_add_test(tc_unix, test_unix);
    tcase_add_test(tc_unix, test_unixinvalidsockets);

    TCase *tc_gethost = tcase_create("GetHost");
    tcase_add_test(tc_gethost, test_gethost_success);
    tcase_add_test(tc_gethost, test_gethost_fail1);
    tcase_add_test(tc_gethost, test_gethost_fail2);
    tcase_set_timeout(tc_gethost, 10);

    suite_add_tcase(s, tc_tcp);
    suite_add_tcase(s, tc_udp);
    suite_add_tcase(s, tc_unix);
    suite_add_tcase(s, tc_gethost);

    return (s);
}

int main(void)
{
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return ((number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}

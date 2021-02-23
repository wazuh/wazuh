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

int __wrap_socket(int __domain, int __type, int __protocol) {
    return mock();//1;
}

int __wrap_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len) {
    return mock(); //1
}

int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen) {
    return mock(); //0
}

int __wrap_getsockopt(int __fd, int __level, int __optname, void *__restrict __optval, socklen_t *__restrict __optlen) {

    int number = 100000;
    void *len = &number;
    memcpy((int*)__optval, (int*)len, sizeof(int));

    return mock(); //0
}

int __wrap_listen(int __fd, int __n) {
    return mock(); //0
}

int __wrap_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len) {
    return mock();//0;
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock();//0;
}

ssize_t __wrap_send(int __fd, const void *__buf, size_t __n, int __flags) {
    return mock();//1;
}

int __wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {

    if(__fd == -1) {
        return mock();
    }

    if(__fd == 3 || __fd == 4 || (__fd == 5 && __n == 13)) {
        char text[BUFFERSIZE];
        strcpy(text, SENDSTRING);
        void *buffer = &text;
        memcpy((char*)__buf, (char*)buffer, sizeof(SENDSTRING));
    } else if(__fd == 5 && __n != 13) {
        uint32_t number = 13;
        void *buffer = &number;
        memcpy((uint32_t*)__buf, (uint32_t*)buffer, sizeof(uint32_t));
    }
    return mock();//1;
}

int __wrap_recvfrom(int __fd, void *__restrict __buf, size_t __n, int __flags, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {

    if(__fd != -1) {
        char text[BUFFERSIZE];
        strcpy(text, SENDSTRING);
        void *buffer = &text;
        memcpy((char*)__buf, (char*)buffer, sizeof(SENDSTRING));
    }

    return mock();//1;
}

int __wrap_chmod(const char *__file, __mode_t __mode) {
    return mock();//1;
}

extern int __real_fcntl(int __fd, int __cmd, unsigned long);
int __wrap_fcntl(int __fd, int __cmd, ...) {

    va_list ap;
    va_start(ap, __cmd);
    unsigned long arg = va_arg(ap, unsigned long);
    va_end(ap);

    if(!test_mode) {
        return __real_fcntl(__fd, __cmd, arg);
    }
    return mock();
}
// Structs

typedef struct test_struct {
    int server_root_socket;
    int server_client_socket;
    int client_socket;
    int server_socket;
    char *ret;
    char *msg;
    char socket_path[256];
} test_struct_t;

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);

    strncpy(init_data->socket_path, "/tmp/tmp_file-XXXXXX", 256);

    *state = init_data;

    test_mode = 1;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    OS_CloseSocket(data->server_socket);
    OS_CloseSocket(data->client_socket);
    OS_CloseSocket(data->server_client_socket);
    OS_CloseSocket(data->server_root_socket);

    unlink(data->socket_path);

    os_free(data->msg);
    os_free(data->ret);
    os_free(data);

    test_mode = 0;

    return OS_SUCCESS;
}

// Tests

void test_bind_TCP_port_ipv4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_listen, 0);

    data->server_root_socket = OS_Bindporttcp(PORT, IPV4, 0);
    assert_return_code(data->server_root_socket, 0);
}

void test_bind_TCP_port_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_listen, 0);

    data->server_root_socket = OS_Bindporttcp(PORT, NULL, 0);
    assert_return_code(data->server_root_socket, 0);
}

void test_bind_TCP_port_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_listen, 0);

    data->server_root_socket = OS_Bindporttcp(PORT, IPV6, 1);
    assert_return_code(data->server_root_socket, 0);
}

void test_connect_TCP_ipv4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectTCP(PORT, IPV4, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_TCP_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectTCP(PORT, IPV6, 1);
    assert_return_code(data->client_socket , 0);
}

void test_accept_TCP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char ipbuffer[BUFFERSIZE];

    data->server_root_socket = 0;
    will_return(__wrap_accept, 0);

    data->server_client_socket = OS_AcceptTCP(data->server_root_socket, ipbuffer, BUFFERSIZE);
    assert_return_code(data->server_client_socket, 0);

    assert_string_equal(ipbuffer, "0.0.0.0");
}

void test_invalid_accept_TCP(void **state) {
    char buffer[BUFFERSIZE];

    will_return(__wrap_accept, -1);

    assert_int_equal(OS_AcceptTCP(-1, buffer, BUFFERSIZE), -1);
}

void test_send_TCP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->client_socket = 3;
    will_return(__wrap_send, 1);

    assert_int_equal(OS_SendTCP(data->client_socket, SENDSTRING), 0);
}

void test_invalid_send_TCP(void **state) {
    will_return(__wrap_send, -6);
    assert_int_equal(OS_SendTCP(-1, SENDSTRING), OS_SOCKTERR);
}

void test_send_secure_TCP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char ipbuffer[BUFFERSIZE];

    data->client_socket = 3;
    will_return(__wrap_send, 17);

    assert_int_equal(OS_SendSecureTCP(data->client_socket, strlen(SENDSTRING), SENDSTRING), 0);
}

void test_send_TCP_by_size(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->server_client_socket = 4;
    will_return(__wrap_send, 6);

    assert_int_equal(OS_SendTCPbySize(data->server_client_socket, 5, SENDSTRING), 0);
}

void test_invalid_send_TCP_by_size(void **state) {
    will_return(__wrap_send, -6);

    assert_int_equal(OS_SendTCPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);
}

void test_recv_TCP_buffer(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char buffer[BUFFERSIZE];

    data->server_client_socket = 4;
    will_return(__wrap_recv, 13);

    assert_int_equal(OS_RecvTCPBuffer(data->server_client_socket, buffer, BUFFERSIZE), 13);
    assert_string_equal(buffer, SENDSTRING);
}

void test_invalid_recv_TCP_buffer(void **state) {
    char buffer[BUFFERSIZE];
    will_return(__wrap_recv, -1);

    assert_int_equal(OS_RecvTCPBuffer(-1, buffer, BUFFERSIZE), -1);
}

void test_recv_TCP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->client_socket = 3;
    will_return(__wrap_recv, 1);

    data->msg = OS_RecvTCP(data->client_socket, BUFFERSIZE);
    assert_non_null(data->msg);

    assert_string_equal(data->msg, SENDSTRING);
}

void test_invalid_recv_TCP(void **state) {
    will_return(__wrap_recv, NULL);
    assert_null(OS_RecvTCP(-1, BUFFERSIZE));
}

void test_recv_secure_TCP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char buffer[BUFFERSIZE];

    data->client_socket = 5;
    will_return(__wrap_recv, 4);
    will_return(__wrap_recv, 13);

    assert_int_equal(OS_RecvSecureTCP(data->client_socket, buffer, BUFFERSIZE), 13);

    assert_string_equal(buffer, SENDSTRING);
}

void test_tcp_invalid_sockets(void **state) {
    char buffer[BUFFERSIZE];
    will_return(__wrap_accept, -1);

    assert_int_equal(OS_AcceptTCP(-1, buffer, BUFFERSIZE), -1);
}

void test_bind_UDP_port_ipv4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);

    data->server_socket = OS_Bindportudp(PORT, IPV4, 0);
    assert_return_code(data->server_socket, 0);
}

void test_bind_UDP_port_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);

    data->server_socket = OS_Bindportudp(PORT, IPV6, 1);
    assert_return_code(data->server_socket, 0);
}

void test_connect_UDP_ipv4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectUDP(PORT, IPV4, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_UDP_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectUDP(PORT, IPV6, 1);
    assert_return_code(data->client_socket , 0);
}

void test_send_UDP_by_size(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->server_client_socket = 4;
    will_return(__wrap_send, 1);

    assert_int_equal(OS_SendUDPbySize(data->client_socket, strlen(SENDSTRING), SENDSTRING), 0);
}

void test_recv_conn_UDP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char buffer[BUFFERSIZE];

    data->server_client_socket = 4;
    will_return(__wrap_recv, 13);

    assert_int_equal(OS_RecvConnUDP(data->server_socket, buffer, BUFFERSIZE), strlen(SENDSTRING));
}

void test_recv_UDP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->server_client_socket = 4;
    will_return(__wrap_recv, 1);

    data->msg = OS_RecvUDP(data->server_client_socket, BUFFERSIZE);
    assert_non_null(data->msg);

    assert_string_equal(data->msg, SENDSTRING);
}

void test_udp_recv_conn_invalid_sockets(void **state) {
    char buffer[BUFFERSIZE];
    will_return(__wrap_recv, -1);

    assert_int_equal(OS_RecvConnUDP(-1, buffer, BUFFERSIZE), 0);
}

void test_udp_send_invalid_sockets(void **state) {
    will_return(__wrap_send, -1);
    assert_int_equal(OS_SendUDPbySize(-1, strlen(SENDSTRING), SENDSTRING), OS_SOCKTERR);
}

void test_udp_recv_invalid_sockets(void **state) {
    will_return(__wrap_recv, -1);
    assert_null(OS_RecvUDP(-1, BUFFERSIZE));
}

void test_recv_unix_invalid_sockets(void **state) {
    char buffer[BUFFERSIZE];
    will_return(__wrap_recvfrom, 0);

    assert_int_equal(OS_RecvUnix(-1, BUFFERSIZE - 1, buffer), 0);
}

void test_send_unix_invalid_sockets(void **state) {
    will_return(__wrap_send, -1);
    assert_int_equal(OS_SendUnix(-1, SENDSTRING, strlen(SENDSTRING)), OS_SOCKTERR);
}

void test_gethost_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    data->ret = OS_GetHost("google-public-dns-a.google.com", 2);

    assert_non_null(data->ret);
    assert_string_equal(data->ret, "8.8.8.8");
}

void test_gethost_null(void **state) {
    assert_null(OS_GetHost(NULL, 2));
}

void test_gethost_not_exists(void **state) {
    assert_null(OS_GetHost("this.should.not.exist", 2));
}

void test_bind_unix_domain(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_chmod, 1);
    will_return(__wrap_fcntl, 0);

    data->server_socket = OS_BindUnixDomain(data->socket_path, SOCK_DGRAM, msg_size);
    assert_return_code(data->server_socket, 0);
}

void test_getsocketsize(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_getsockopt, 0);

    assert_return_code(OS_getsocketsize(data->server_socket), msg_size);
}

void test_connect_unix_domain(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);

    data->client_socket = OS_ConnectUnixDomain(data->socket_path, SOCK_DGRAM, msg_size);
    assert_return_code(data->client_socket , 0);
}

void test_send_unix(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->client_socket = 3;
    will_return(__wrap_send, 15);

    assert_int_equal(OS_SendUnix(data->client_socket, SENDSTRING, 0), 0);
}

void test_recv_unix(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char buffer[BUFFERSIZE];

    data->server_client_socket = 4;
    will_return(__wrap_recvfrom, 14);

    assert_int_equal(OS_RecvUnix(data->server_socket, BUFFERSIZE - 1, buffer), strlen(SENDSTRING) + 1);
    assert_string_equal(buffer, SENDSTRING);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Bind a TCP port */
        cmocka_unit_test_setup_teardown(test_bind_TCP_port_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_bind_TCP_port_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_bind_TCP_port_ipv6, test_setup, test_teardown),

        /* Open a TCP socket */
        cmocka_unit_test_setup_teardown(test_connect_TCP_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_connect_TCP_ipv6, test_setup, test_teardown),

        /* Accept a TCP connection */
        cmocka_unit_test_setup_teardown(test_accept_TCP, test_setup, test_teardown),
        cmocka_unit_test(test_invalid_accept_TCP),

        /* Send a TCP packet */
        cmocka_unit_test_setup_teardown(test_send_TCP, test_setup, test_teardown),
        cmocka_unit_test(test_invalid_send_TCP),

        /* Send secure TCP message */
        cmocka_unit_test_setup_teardown(test_send_secure_TCP, test_setup, test_teardown),

        /* Receive a TCP packet */
        cmocka_unit_test_setup_teardown(test_recv_TCP_buffer, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_recv_TCP, test_setup, test_teardown),
        cmocka_unit_test(test_invalid_recv_TCP),
        cmocka_unit_test(test_invalid_recv_TCP_buffer),

        /* Receive secure TCP message */
        cmocka_unit_test_setup_teardown(test_recv_secure_TCP, test_setup, test_teardown),

        /* Send a TCP packet of a specific size */
        cmocka_unit_test_setup_teardown(test_send_TCP_by_size, test_setup, test_teardown),
        cmocka_unit_test(test_invalid_send_TCP_by_size),
        cmocka_unit_test(test_tcp_invalid_sockets),

        /* Bind a UDP port */
        cmocka_unit_test_setup_teardown(test_bind_UDP_port_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_bind_UDP_port_ipv6, test_setup, test_teardown),

        /* Open a UDP socket */
        cmocka_unit_test_setup_teardown(test_connect_UDP_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_connect_UDP_ipv6, test_setup, test_teardown),

        /* Send a UDP packet */
        cmocka_unit_test_setup_teardown(test_send_UDP_by_size, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_udp_send_invalid_sockets, test_setup, test_teardown),

        /* Receive a UDP packet */
        cmocka_unit_test_setup_teardown(test_recv_conn_UDP, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_recv_UDP, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_udp_recv_conn_invalid_sockets, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_udp_recv_invalid_sockets, test_setup, test_teardown),

        /* Bind a unix domain */
        cmocka_unit_test_setup_teardown(test_bind_unix_domain, test_setup, test_teardown),

        /* Get current maximum size */
        cmocka_unit_test_setup_teardown(test_getsocketsize, test_setup, test_teardown),

        /* Connect unix domain */
        cmocka_unit_test_setup_teardown(test_connect_unix_domain, test_setup, test_teardown),

        /* Send a message using a Unix socket */
        cmocka_unit_test_setup_teardown(test_send_unix, test_setup, test_teardown),

        /* Receive a message using a Unix socket */
        cmocka_unit_test_setup_teardown(test_recv_unix, test_setup, test_teardown),

        /* Calls gethostbyname */
        cmocka_unit_test(test_gethost_null),
        cmocka_unit_test(test_gethost_not_exists),
        cmocka_unit_test_setup_teardown(test_gethost_success, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

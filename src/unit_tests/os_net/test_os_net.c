/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "shared.h"
#include "os_err.h"
#include "sym_load.h"
#include "../../data_provider/include/sysInfo.h"
#include "../../headers/shared.h"
#include "../../os_net/os_net.h"

#include "../wrappers/common.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

#define IPV4 "127.0.0.1"
#define IPV6 "::1"
#define IPV6_LINK_LOCAL "FE80:0000:0000:0000:ABCD:ABCD:ABCD:ABCD"
#define PORT 4321
#define SENDSTRING "Hello World!\n"
#define BUFFERSIZE 1024

int __wrap_getuid(void) {
    return mock();
}

int __wrap_getgid(void) {
    return mock();
}

// Structs

typedef struct test_struct {
    int server_root_socket;
    int server_client_socket;
    int client_socket;
    int server_socket;
    int timeout;
    char *ret;
    char *msg;
    char socket_path[256];
    struct addrinfo *addr;
} test_struct_t;

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);

    os_calloc(1, sizeof(struct addrinfo), init_data->addr);
    os_calloc(1, sizeof(struct sockaddr), init_data->addr->ai_addr);
    init_data->timeout = 1;

    strncpy(init_data->socket_path, "/tmp/tmp_file-XXXXXX", 256);

    *state = init_data;

    test_mode = 1;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    unlink(data->socket_path);

    os_free(data->addr->ai_addr);
    os_free(data->addr);

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
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectTCP(PORT, IPV4, 0, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_TCP_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectTCP(PORT, IPV6, 1, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_TCP_ipv6_link_local_no_interface(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    expect_string(__wrap__minfo, formatted_msg, "No network interface provided to use with link-local IPv6 address.");

    data->client_socket = OS_ConnectTCP(PORT, IPV6_LINK_LOCAL, 1, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_TCP_ipv6_link_local_with_interface(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectTCP(PORT, IPV6_LINK_LOCAL, 1, 1);
    assert_return_code(data->client_socket , 0);
}

void test_accept_TCP(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char ipbuffer[BUFFERSIZE];

    data->server_root_socket = 0;
    will_return(__wrap_accept, AF_INET);
    will_return(__wrap_accept, 0);

    data->server_client_socket = OS_AcceptTCP(data->server_root_socket, ipbuffer, BUFFERSIZE);
    assert_return_code(data->server_client_socket, 0);

    assert_string_equal(ipbuffer, "0.0.0.0");
}

void test_invalid_accept_TCP(void **state) {
    char buffer[BUFFERSIZE];

    will_return(__wrap_accept, AF_INET);
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
    will_return(__wrap_accept, AF_INET);
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
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectUDP(PORT, IPV4, 0, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_UDP_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 4);
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectUDP(PORT, IPV6, 1, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_UDP_ipv6_link_local_no_interface(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    expect_string(__wrap__minfo, formatted_msg, "No network interface provided to use with link-local IPv6 address.");

    data->client_socket = OS_ConnectUDP(PORT, IPV6_LINK_LOCAL, 1, 0);
    assert_return_code(data->client_socket , 0);
}

void test_connect_UDP_ipv6_link_local_with_interface(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_getsockopt, 0);

    data->client_socket = OS_ConnectUDP(PORT, IPV6_LINK_LOCAL, 1, 1);
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
    char buffer[BUFFERSIZE + 1];

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
    char buffer[BUFFERSIZE + 1];
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
    char *hostname = "google-public-dns-a.google.com";

    data->addr->ai_family = AF_INET;
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)data->addr->ai_addr;
    ipv4->sin_addr.s_addr = 134744072;

    expect_string(__wrap_getaddrinfo, node, hostname);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);

    data->ret = OS_GetHost(hostname, 2);

    assert_non_null(data->ret);
    assert_string_equal(data->ret, "8.8.8.8");
}

void test_gethost_null(void **state) {
    assert_null(OS_GetHost(NULL, 2));
}

void test_gethost_not_exists(void **state) {
    char *hostname = "this.should.not.exist";

    expect_string_count(__wrap_getaddrinfo, node, hostname, 3);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);

    expect_value_count(__wrap_sleep, seconds, 1, 3);

    assert_null(OS_GetHost(hostname, 2));
}

void test_bind_unix_domain(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_getuid, 0);
    will_return(__wrap_getgid, 995);
    will_return(__wrap_socket, 3);
    will_return(__wrap_bind, 1);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);

    expect_string(__wrap_chmod, path, data->socket_path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_chown, __file, data->socket_path);
    expect_value(__wrap_chown, __owner, 0);
    expect_value(__wrap_chown, __group, 995);
    will_return(__wrap_chown, 0);

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

void test_send_secure_TCP_cluster_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char req[] = "command";
    data->client_socket = 3;

    will_return(__wrap_send, 5);
    assert_int_equal(OS_SendSecureTCPCluster(data->client_socket, req , SENDSTRING, strlen(SENDSTRING)) , OS_SOCKTERR);
}

void test_send_secure_TCP_cluster_command_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->client_socket = 3;

    expect_string(__wrap__merror, formatted_msg, "Empty command, not sending message to cluster");
    assert_int_equal(OS_SendSecureTCPCluster(data->client_socket, NULL , SENDSTRING, strlen(SENDSTRING)), -1);
}

void test_send_secure_TCP_cluster_max_payload_exceeded(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    const unsigned MAX_PAYLOAD_SIZE = 1000001;

    char req[] = "command";
    data->client_socket = 3;

    expect_string(__wrap__merror, formatted_msg, "Data of length 1000001 exceeds maximum allowed 1000000");
    assert_int_equal(OS_SendSecureTCPCluster(data->client_socket, req, SENDSTRING, MAX_PAYLOAD_SIZE), -1);
}

void test_send_secure_TCP_cluster_command_size_exceeded(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    const unsigned COMMAND_SIZE = 12;

    char req[] = "command size exceeded";
    data->client_socket = 3;

    expect_string(__wrap__merror, formatted_msg, "Command of length 21 exceeds maximum allowed 12");
    assert_int_equal(OS_SendSecureTCPCluster(data->client_socket, req, SENDSTRING, strlen(SENDSTRING)), -1);
}

void test_recv_secure_cluster_TCP_socket_error(void **state) {
	test_struct_t *data  = (test_struct_t *)*state;
	char ret [BUFFERSIZE];

	will_return(__wrap_recv, -1);
	data->client_socket = -1;

	assert_int_equal(OS_RecvSecureClusterTCP(data->client_socket, ret, sizeof(ret)), -1);
}

void test_recv_secure_cluster_TCP_socket_disconected_or_timeout(void **state) {
	test_struct_t *data  = (test_struct_t *)*state;
	char ret [BUFFERSIZE];

	will_return(__wrap_recv, 0);
	data->client_socket = -1;

	assert_int_equal(OS_RecvSecureClusterTCP(data->client_socket, ret, sizeof(ret)), 0);
}

void test_recv_secure_cluster_TCP_wrong_header(void **state) {
	test_struct_t *data  = (test_struct_t *)*state;
	char ret [BUFFERSIZE];

	will_return_always(__wrap_recv, 7);
	data->client_socket = -1;

	assert_int_equal(OS_RecvSecureClusterTCP(data->client_socket, ret, sizeof(ret)), -1);
}

void test_recv_secure_cluster_TCP_cmd_error(void **state) {
	test_struct_t *data  = (test_struct_t *)*state;
	char ret [BUFFERSIZE];

	will_return_always(__wrap_recv, 20);
	data->client_socket = 7;

	assert_int_equal(OS_RecvSecureClusterTCP(data->client_socket, ret, sizeof(ret)), -2);
}

void test_resolve_hostname_success(void ** state){
    test_struct_t *data  = (test_struct_t *)*state;

    data->addr->ai_family = AF_INET;
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)data->addr->ai_addr;
    ipv4->sin_addr.s_addr = 134744072;

    os_strdup("localhost", data->ret);

    expect_string(__wrap_getaddrinfo, node, "localhost");
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);

    expect_string(__wrap_OS_IsValidIP, ip_address, data->ret);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    resolve_hostname(&data->ret, 5);

    assert_string_equal(data->ret, "localhost/8.8.8.8");
}

void test_resolve_hostname_valid_ip(void ** state){
    char *hostname = "8.8.8.8";

    expect_string(__wrap_OS_IsValidIP, ip_address, hostname);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    resolve_hostname(&hostname, 5);
}

void test_resolve_hostname_not_resolved(void ** state){
    test_struct_t *data  = (test_struct_t *)*state;

    os_strdup("localhost", data->ret);

    expect_string(__wrap_OS_IsValidIP, ip_address, data->ret);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    expect_string_count(__wrap_getaddrinfo, node, "localhost", 6);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);
    will_return(__wrap_getaddrinfo, NULL);
    will_return(__wrap_getaddrinfo, -1);

    expect_value_count(__wrap_sleep, seconds, 1, 6);

    resolve_hostname(&data->ret, 5);

    assert_string_equal(data->ret, "localhost/");
}

void test_get_ip_from_resolved_hostname_ip(void ** state){
    const char *resolved_hostname = "localhost/8.8.8.8";

    const char *ret = get_ip_from_resolved_hostname(resolved_hostname);

    assert_string_equal(ret, "8.8.8.8");
}

void test_get_ip_from_resolved_hostname_no_ip(void ** state){
    const char *resolved_hostname = "localhost/";

    const char *ret = get_ip_from_resolved_hostname(resolved_hostname);

    assert_string_equal(ret, "");
}

// Tests external_socket_connect

void test_external_socket_connect_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    int ret = external_socket_connect(data->socket_path, data->timeout);
    assert_int_equal(ret, 4);
}


void test_external_socket_connect_failed_sent_timeout(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, -1);

    int ret = external_socket_connect(data->socket_path, data->timeout);
    assert_int_equal(ret, -1);
}

void test_external_socket_connect_failed_receive_timeout(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int msg_size = 1;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, -1);

    int ret = external_socket_connect(data->socket_path, data->timeout);
    assert_int_equal(ret, -1);
}

void get_ipv4_string_fail_size(void ** state) {

    char address[IPSIZE] = {0};
    struct in_addr addr;

#ifndef WIN32
    addr.s_addr = 0x0F0F0F0F;
#else
    addr.u.Byte = 0x0F0F0F0F;
#endif

    int ret = get_ipv4_string(addr, address, 1);

    assert_string_equal(address, "");
    assert_int_equal(ret, OS_INVALID);
}

void get_ipv4_string_success(void ** state) {

    char address[IPSIZE] = {0};
    struct in_addr addr;

#ifndef WIN32
    addr.s_addr = 0x0F0F0F0F;
#else
    addr.u.Byte = 0x0F0F0F0F;
#endif

    int ret = get_ipv4_string(addr, address, IPSIZE);

    assert_string_equal(address, "15.15.15.15");
    assert_int_equal(ret, OS_SUCCESS);
}

void get_ipv6_string_fail_size(void ** state) {

    char address[IPSIZE] = {0};
    struct in6_addr addr6;

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        addr6.s6_addr[i] = 0x00;
#else
        addr6.u.Byte[i] = 0x00;
#endif
    }

    int ret = get_ipv6_string(addr6, address, 1);

    assert_string_equal(address, "");
    assert_int_equal(ret, OS_INVALID);
}

void get_ipv6_string_success(void ** state) {

    char address[IPSIZE] = {0};
    struct in6_addr addr6;

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        addr6.s6_addr[i] = 0x10;
#else
        addr6.u.Byte[i] = 0x10;
#endif

    }

    expect_string(__wrap_OS_GetIPv4FromIPv6, ip_address, "1010:1010:1010:1010:1010:1010:1010:1010");
    expect_value(__wrap_OS_GetIPv4FromIPv6, size, IPSIZE);
    will_return(__wrap_OS_GetIPv4FromIPv6, 0);

    expect_string(__wrap_OS_ExpandIPv6, ip_address, "1010:1010:1010:1010:1010:1010:1010:1010");
    expect_value(__wrap_OS_ExpandIPv6, size, IPSIZE);
    will_return(__wrap_OS_ExpandIPv6, 0);

    int ret = get_ipv6_string(addr6, address, IPSIZE);

    assert_string_equal(address, "1010:1010:1010:1010:1010:1010:1010:1010");
    assert_int_equal(ret, OS_SUCCESS);
}

void get_ipv4_numeric_fail(void ** state) {

    const char *address = "Not a valid IP";
    struct in_addr addr;

#ifndef WIN32
    addr.s_addr = 0;
#else
    addr.u.Byte = 0;
#endif

    int ret = get_ipv4_numeric(address, &addr);

    assert_int_equal(ret, OS_INVALID);
}

void get_ipv4_numeric_success(void ** state) {

    const char *address = "15.15.15.15";
    struct in_addr addr;

#ifndef WIN32
    addr.s_addr = 0;
#else
    addr.u.Byte = 0;
#endif

    int ret = get_ipv4_numeric(address, &addr);

    assert_int_equal(ret, OS_SUCCESS);

#ifndef WIN32
    assert_int_equal(addr.s_addr, 0x0F0F0F0F);
#else
    assert_int_equal(addr.u.Byte, 0x0F0F0F0F);
#endif
}

void get_ipv6_numeric_fail(void ** state) {

    const char *address = "Not a valid IP";
    struct in6_addr addr6;

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        addr6.s6_addr[i] = 0;
#else
        addr6.u.Byte[i] = 0;
#endif
    }

    int ret = get_ipv6_numeric(address, &addr6);

    assert_int_equal(ret, OS_INVALID);

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        assert_int_equal(addr6.s6_addr[i], 0);
#else
        assert_int_equal(addr6.u.Byte[i], 0);
#endif
    }
}

void get_ipv6_numeric_success(void ** state) {

    const char *address = "1010:1010:1010:1010:1010:1010:1010:1010";
    struct in6_addr addr6;

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        addr6.s6_addr[i] = 0;
#else
        addr6.u.Byte[i] = 0;
#endif
    }

    int ret = get_ipv6_numeric(address, &addr6);

    assert_int_equal(ret, OS_SUCCESS);

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        assert_int_equal(addr6.s6_addr[i], 0x10);
#else
        assert_int_equal(addr6.u.Byte[i], 0x10);
#endif
    }
}

void get_ipv6_numeric_compare_compres_ipv6(void ** state) {

    const char *address = "fd17:625c:f037::45ea:97eb";
    const char *address2 = "fd17:625c:f037:0:0:0:45ea:97eb";

    struct in6_addr addr6;
    struct in6_addr addr6_2;

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        addr6.s6_addr[i] = 0;
        addr6_2.s6_addr[i] = 0;
#else
        addr6.u.Byte[i] = 0;
        addr6_2.u.Byte[i] = 0;
#endif
    }

    int ret = get_ipv6_numeric(address, &addr6);

    assert_int_equal(ret, OS_SUCCESS);

    ret = get_ipv6_numeric(address2, &addr6_2);

    assert_int_equal(ret, OS_SUCCESS);

    for(unsigned int i = 0; i < 16 ; i++) {
#ifndef WIN32
        assert_int_equal(addr6.s6_addr[i], addr6_2.s6_addr[i]);
#else
        assert_int_equal(addr6.u.Byte[i], addr6_2.u.Byte[i]);
#endif
    }
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
        cmocka_unit_test_setup_teardown(test_connect_TCP_ipv6_link_local_no_interface, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_connect_TCP_ipv6_link_local_with_interface, test_setup, test_teardown),

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
        cmocka_unit_test_setup_teardown(test_connect_UDP_ipv6_link_local_no_interface, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_connect_UDP_ipv6_link_local_with_interface, test_setup, test_teardown),

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
        cmocka_unit_test(test_send_unix_invalid_sockets),

        /* Receive a message using a Unix socket */
        cmocka_unit_test_setup_teardown(test_recv_unix, test_setup, test_teardown),

        /* Call OS_GetHost */
        cmocka_unit_test(test_gethost_null),
        cmocka_unit_test(test_gethost_not_exists),
        cmocka_unit_test_setup_teardown(test_gethost_success, test_setup, test_teardown),

        /* Send secure TCP Cluster message */
        cmocka_unit_test_setup_teardown(test_send_secure_TCP_cluster_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_secure_TCP_cluster_command_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_secure_TCP_cluster_max_payload_exceeded, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_secure_TCP_cluster_command_size_exceeded, test_setup, test_teardown),

        /* Receive secure TCP Cluster message */
        cmocka_unit_test_setup_teardown(test_recv_secure_cluster_TCP_socket_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_recv_secure_cluster_TCP_socket_disconected_or_timeout, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_recv_secure_cluster_TCP_wrong_header, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_recv_secure_cluster_TCP_cmd_error, test_setup, test_teardown),

        /* Test for resolve_hostname */
        cmocka_unit_test_setup_teardown(test_resolve_hostname_success, test_setup, test_teardown),
        cmocka_unit_test(test_resolve_hostname_valid_ip),
        cmocka_unit_test_setup_teardown(test_resolve_hostname_not_resolved, test_setup, test_teardown),

        /* Test for get_ip_from_resolved_hostname */
        cmocka_unit_test(test_get_ip_from_resolved_hostname_ip),
        cmocka_unit_test(test_get_ip_from_resolved_hostname_no_ip),

        /* Test for external_socket_connect */
        cmocka_unit_test_setup_teardown(test_external_socket_connect_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_external_socket_connect_failed_sent_timeout, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_external_socket_connect_failed_receive_timeout, test_setup, test_teardown),

        /* Test get_ipv4_string */
        cmocka_unit_test(get_ipv4_string_fail_size),
        cmocka_unit_test(get_ipv4_string_success),

        /* Test get_ipv6_string */
        cmocka_unit_test(get_ipv6_string_fail_size),
        cmocka_unit_test(get_ipv6_string_success),

        /* Test get_ipv4_numeric */
        cmocka_unit_test(get_ipv4_numeric_fail),
        cmocka_unit_test(get_ipv4_numeric_success),

        /* Test get_ipv6_numeric */
        cmocka_unit_test(get_ipv6_numeric_fail),
        cmocka_unit_test(get_ipv6_numeric_success),
        cmocka_unit_test(get_ipv6_numeric_compare_compres_ipv6),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

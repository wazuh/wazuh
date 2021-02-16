/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include "../wazuh_modules/wmodules.h"
#include "../../os_net/os_net.h"

int __wrap_listen(int __fd, int __n){

    check_expected(__fd);
    check_expected(__n);

    return (int) mock();
}

int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen){

    check_expected(__fd);
    check_expected(__level);
    check_expected(__optname);
    check_expected(__optval);
    check_expected(__optlen);

    return (int) mock();
}

int __wrap_socket(int __domain, int __type, int __protocol){

    check_expected(__domain);
    check_expected(__type);
    check_expected(__protocol);

    return (int) mock();
}

int __wrap_bind(int __fd, const struct sockaddr *__addr, socklen_t __len){

    check_expected(__fd);
    check_expected(__addr);
    check_expected(__len);

    return (int) mock();
}

static void test_os_net_udp_linux(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int return_value_bind = 1;
    int return_value_listen = 1;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_DGRAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_UDP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_bind, __fd,test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind,return_value_bind);

    int ossock = OS_Bindportudp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,test_ossock);

}

static void test_os_net_tcp_linux(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int return_value_bind = 1;
    int return_value_listen = 1;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, return_value_socket);

    expect_value(__wrap_setsockopt,__fd,return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt,__optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt,__optval);
    expect_any(__wrap_setsockopt,__optlen);
    will_return(__wrap_setsockopt,return_value_setsockopt);

    expect_value(__wrap_bind, __fd,test_ossock);
    expect_any(__wrap_bind, __addr);
    expect_any(__wrap_bind, __len);
    will_return(__wrap_bind, test_ossock);

    expect_value(__wrap_listen, __fd, test_ossock);
    expect_value(__wrap_listen, __n, BACKLOG);
    will_return(__wrap_listen,return_value_listen);

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,test_ossock);

}

static void test_os_net_udp_linux_fail_socket(void **state){
    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int bad_test_ossock = -1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_DGRAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_UDP);
    will_return(__wrap_socket, bad_test_ossock);

    int ossock = OS_Bindportudp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);
}

static void test_os_net_tcp_linux_fail_socket(void **state){
    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int bad_test_ossock = -1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, bad_test_ossock);

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);
}

static void test_os_net_tcp_linux_fail_setsockopt(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int bad_return_value_setsockopt = -1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, return_value_socket);

    expect_value(__wrap_setsockopt,__fd,return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt,__optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt,__optval);
    expect_any(__wrap_setsockopt,__optlen);

    will_return(__wrap_setsockopt,bad_return_value_setsockopt);

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);
}

static void test_os_net_tcp_linux_fail_listen(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int return_value_bind = 1;
    int bad_return_value_listen = -1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, return_value_socket);

    expect_value(__wrap_setsockopt,__fd,return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt,__optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt,__optval);
    expect_any(__wrap_setsockopt,__optlen);
    will_return(__wrap_setsockopt,return_value_setsockopt);

    expect_value(__wrap_bind, __fd,test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind, test_ossock);

    expect_value(__wrap_listen, __fd, test_ossock);
    expect_value(__wrap_listen, __n, BACKLOG);
    will_return(__wrap_listen,bad_return_value_listen);

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);

}

static void test_os_net_udp_linux_ipv6_fail_bind(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int bad_return_value_bind = -1;
    int return_value_listen = 1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_DGRAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_UDP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind, bad_return_value_bind);

    int ossock = OS_Bindportudp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);

}

static void test_os_net_udp_linux_notipv6_fail_bind(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 0;
    int test_ossock = 1;
    int bad_return_value_bind = -1;
    int return_value_listen = 1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET);
    expect_value(__wrap_socket,__type,SOCK_DGRAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_UDP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind, bad_return_value_bind);

    int ossock = OS_Bindportudp(test_port, test_ip, test_ipv6);

    assert_int_equal(ossock, err);

}

static void test_os_net_tcp_linux_ipv6_fail_bind(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int bad_return_value_bind = -1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_setsockopt,__fd, return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt,__optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt,__optval);
    expect_any(__wrap_setsockopt,__optlen);
    will_return(__wrap_setsockopt, return_value_setsockopt);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind, bad_return_value_bind);

    int ossock = OS_Bindporttcp(test_port, test_ip, test_ipv6);

    assert_int_equal(ossock, err);

}

static void test_os_net_tcp_linux_notipv6_fail_bind(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 0;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int bad_return_value_bind = -1;
    int err = OS_SOCKTERR;

    expect_value(__wrap_socket,__domain,PF_INET);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_setsockopt,__fd,return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt,__optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt,__optval);
    expect_any(__wrap_setsockopt,__optlen);
    will_return(__wrap_setsockopt,return_value_setsockopt);

    expect_value(__wrap_bind, __fd,test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind,bad_return_value_bind);

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_os_net_udp_linux),
        cmocka_unit_test(test_os_net_tcp_linux),
        cmocka_unit_test(test_os_net_udp_linux_fail_socket),
        cmocka_unit_test(test_os_net_tcp_linux_fail_socket),
        cmocka_unit_test(test_os_net_tcp_linux_fail_setsockopt),
        cmocka_unit_test(test_os_net_tcp_linux_fail_listen),
        cmocka_unit_test(test_os_net_udp_linux_ipv6_fail_bind),
        cmocka_unit_test(test_os_net_udp_linux_notipv6_fail_bind),
        cmocka_unit_test(test_os_net_tcp_linux_ipv6_fail_bind),
        cmocka_unit_test(test_os_net_tcp_linux_notipv6_fail_bind)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

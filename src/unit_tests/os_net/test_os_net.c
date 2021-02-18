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

int __wrap_listen(int __fd, int __n) {

    check_expected(__fd);
    check_expected(__n);

    return (int) mock();
}

int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen) {

    check_expected(__fd);
    check_expected(__level);
    check_expected(__optname);
    check_expected(__optval);
    check_expected(__optlen);

    return (int) mock();
}

int __wrap_socket(int __domain, int __type, int __protocol) {

    check_expected(__domain);
    check_expected(__type);
    check_expected(__protocol);

    return (int) mock();
}

int __wrap_bind(int __fd, const struct sockaddr *__addr, socklen_t __len) {

    check_expected(__fd);
    check_expected(__addr);
    check_expected(__len);

    return (int) mock();
}

static void test_OS_Bindportudp_success(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int return_value_bind = 1;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket,af,PF_INET);
    expect_value(wrap_socket,type,SOCK_DGRAM);
    expect_value(wrap_socket,protocol,IPPROTO_UDP);
    will_return(wrap_socket, test_ossock);

    expect_value(wrap_bind, s,test_ossock);
    expect_any(wrap_bind,addr);
    expect_any(wrap_bind,namelen);
    will_return(wrap_bind,return_value_bind);

#else

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_DGRAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_UDP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_bind, __fd,test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind,return_value_bind);

#endif

    int ossock = OS_Bindportudp(test_port,test_ip,test_ipv6);
    assert_int_equal(ossock,test_ossock);

}

static void test_OS_Bindporttcp_success(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int return_value_bind = 1;
    int return_value_listen = 1;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket, af, PF_INET);
    expect_value(wrap_socket, type, SOCK_STREAM);
    expect_value(wrap_socket, protocol, IPPROTO_TCP);
    will_return(wrap_socket, return_value_socket);

    expect_any(wrap_setsockopt,s);
    expect_value(wrap_setsockopt, level, SOL_SOCKET);
    expect_value(wrap_setsockopt,optname, SO_REUSEADDR);
    expect_any(wrap_setsockopt,optval);
    expect_any(wrap_setsockopt,optlen);
    will_return(wrap_setsockopt,return_value_setsockopt);

    expect_value(wrap_bind, s,test_ossock);
    expect_any(wrap_bind, addr);
    expect_any(wrap_bind, namelen);
    will_return(wrap_bind, test_ossock);

    expect_value(wrap_listen, s, test_ossock);
    expect_value(wrap_listen, backlog, BACKLOG);
    will_return(wrap_listen, return_value_listen);

#else

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

#endif

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);
    assert_int_equal(ossock,test_ossock);

}

static void test_OS_Bindportudp_fail_socket(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int bad_test_ossock = -1;
    int err = OS_SOCKTERR;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket,af,PF_INET);
    expect_value(wrap_socket,type,SOCK_DGRAM);
    expect_value(wrap_socket,protocol,IPPROTO_UDP);
    will_return(wrap_socket, bad_test_ossock);

#else

    expect_value(__wrap_socket,__domain,PF_INET);
    expect_value(__wrap_socket,__type,SOCK_DGRAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_UDP);
    will_return(__wrap_socket, bad_test_ossock);

#endif

    int ossock = OS_Bindportudp(test_port,test_ip,test_ipv6);
    assert_int_equal(ossock,err);

}

static void test_OS_Bindporttcp_fail_socket(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int bad_test_ossock = -1;
    int err = OS_SOCKTERR;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket,af,PF_INET);
    expect_value(wrap_socket,type,SOCK_STREAM);
    expect_value(wrap_socket,protocol,IPPROTO_TCP);
    will_return(wrap_socket, bad_test_ossock);

#else

    expect_value(__wrap_socket,__domain,PF_INET6);
    expect_value(__wrap_socket,__type,SOCK_STREAM);
    expect_value(__wrap_socket,__protocol,IPPROTO_TCP);
    will_return(__wrap_socket, bad_test_ossock);

#endif

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);
    assert_int_equal(ossock,err);
}

static void test_OS_Bindporttcp_fail_setsockopt(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int bad_return_value_setsockopt = -1;
    int err = OS_SOCKTERR;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket,af,PF_INET);
    expect_value(wrap_socket,type,SOCK_STREAM);
    expect_value(wrap_socket,protocol,IPPROTO_TCP);
    will_return(wrap_socket, return_value_socket);

    expect_value(wrap_setsockopt,s,return_value_socket);
    expect_value(wrap_setsockopt, level, SOL_SOCKET);
    expect_value(wrap_setsockopt,optname, SO_REUSEADDR);
    expect_any(wrap_setsockopt,optval);
    expect_any(wrap_setsockopt,optlen);
    will_return(wrap_setsockopt,bad_return_value_setsockopt);

#else

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

#endif

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);

    assert_int_equal(ossock,err);
}

static void test_OS_Bindporttcp_fail_listen(void **state) {

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

#ifdef TEST_WINAGENT

    expect_value(wrap_socket,af,PF_INET);
    expect_value(wrap_socket,type,SOCK_STREAM);
    expect_value(wrap_socket,protocol,IPPROTO_TCP);
    will_return(wrap_socket, return_value_socket);

    expect_value(wrap_setsockopt,s,return_value_socket);
    expect_value(wrap_setsockopt, level, SOL_SOCKET);
    expect_value(wrap_setsockopt,optname, SO_REUSEADDR);
    expect_any(wrap_setsockopt,optval);
    expect_any(wrap_setsockopt,optlen);
    will_return(wrap_setsockopt,return_value_setsockopt);

    expect_value(wrap_bind, s,test_ossock);
    expect_any(wrap_bind,addr);
    expect_any(wrap_bind,namelen);
    will_return(wrap_bind, test_ossock);

    expect_value(wrap_listen, s, test_ossock);
    expect_value(wrap_listen, backlog, BACKLOG);
    will_return(wrap_listen,bad_return_value_listen);

#else

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

#endif

    int ossock = OS_Bindporttcp(test_port,test_ip,test_ipv6);
    assert_int_equal(ossock,err);

}

static void test_OS_Bindportudp_ipv6_fail_bind(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int bad_return_value_bind = -1;
    int return_value_listen = 1;
    int err = OS_SOCKTERR;

#ifndef TEST_WINAGENT

    expect_value(__wrap_socket, __domain, PF_INET6);
    expect_value(__wrap_socket, __type, SOCK_DGRAM);
    expect_value(__wrap_socket, __protocol,IPPROTO_UDP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind,__addr);
    expect_any(__wrap_bind,__len);
    will_return(__wrap_bind, bad_return_value_bind);

    int ossock = OS_Bindportudp(test_port,test_ip,test_ipv6);
    assert_int_equal(ossock,err);

#else

    assert(true);

#endif

}

static void test_OS_Bindportudp_no_ipv6_fail_bind(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 0;
    int test_ossock = 1;
    int bad_return_value_bind = -1;
    int return_value_listen = 1;
    int err = OS_SOCKTERR;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket, af, PF_INET);
    expect_value(wrap_socket, type, SOCK_DGRAM);
    expect_value(wrap_socket, protocol, IPPROTO_UDP);
    will_return(wrap_socket, test_ossock);

    expect_value(wrap_bind, s, test_ossock);
    expect_any(wrap_bind, addr);
    expect_any(wrap_bind, namelen);
    will_return(wrap_bind, bad_return_value_bind);

#else

    expect_value(__wrap_socket, __domain, PF_INET);
    expect_value(__wrap_socket, __type, SOCK_DGRAM);
    expect_value(__wrap_socket, __protocol, IPPROTO_UDP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind, __addr);
    expect_any(__wrap_bind, __len);
    will_return(__wrap_bind, bad_return_value_bind);

#endif

    int ossock = OS_Bindportudp(test_port, test_ip, test_ipv6);
    assert_int_equal(ossock, err);

}

static void test_OS_Bindporttcp_ipv6_fail_bind(void **state) {

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 1;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int bad_return_value_bind = -1;
    int err = OS_SOCKTERR;

#ifndef TEST_WINAGENT

    expect_value(__wrap_socket, __domain, PF_INET6);
    expect_value(__wrap_socket, __type, SOCK_STREAM);
    expect_value(__wrap_socket, __protocol, IPPROTO_TCP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_setsockopt,__fd, return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt,__optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt,__optval);
    expect_any(__wrap_setsockopt,__optlen);
    will_return(__wrap_setsockopt, return_value_setsockopt);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind, __addr);
    expect_any(__wrap_bind, __len);
    will_return(__wrap_bind, bad_return_value_bind);

    int ossock = OS_Bindporttcp(test_port, test_ip, test_ipv6);
    assert_int_equal(ossock, err);

#else

    assert(true);

#endif

}

static void test_OS_Bindporttcp_no_ipv6_fail_bind(void **state){

    u_int16_t test_port = 1;
    const char* test_ip = NULL;
    int test_ipv6 = 0;
    int test_ossock = 1;
    int test_flag = 1;
    int return_value_socket = 1;
    int return_value_setsockopt = 1;
    int bad_return_value_bind = -1;
    int err = OS_SOCKTERR;

#ifdef TEST_WINAGENT

    expect_value(wrap_socket, af, PF_INET);
    expect_value(wrap_socket, type, SOCK_STREAM);
    expect_value(wrap_socket, protocol, IPPROTO_TCP);
    will_return(wrap_socket, test_ossock);

    expect_value(wrap_setsockopt, s, return_value_socket);
    expect_value(wrap_setsockopt, level, SOL_SOCKET);
    expect_value(wrap_setsockopt, optname, SO_REUSEADDR);
    expect_any(wrap_setsockopt, optval);
    expect_any(wrap_setsockopt, optlen);
    will_return(wrap_setsockopt, return_value_setsockopt);

    expect_value(wrap_bind, s, test_ossock);
    expect_any(wrap_bind, addr);
    expect_any(wrap_bind, namelen);
    will_return(wrap_bind, bad_return_value_bind);

#else

    expect_value(__wrap_socket, __domain, PF_INET);
    expect_value(__wrap_socket, __type, SOCK_STREAM);
    expect_value(__wrap_socket, __protocol, IPPROTO_TCP);
    will_return(__wrap_socket, test_ossock);

    expect_value(__wrap_setsockopt, __fd, return_value_socket);
    expect_value(__wrap_setsockopt, __level, SOL_SOCKET);
    expect_value(__wrap_setsockopt, __optname, SO_REUSEADDR);
    expect_any(__wrap_setsockopt, __optval);
    expect_any(__wrap_setsockopt, __optlen);
    will_return(__wrap_setsockopt, return_value_setsockopt);

    expect_value(__wrap_bind, __fd, test_ossock);
    expect_any(__wrap_bind, __addr);
    expect_any(__wrap_bind, __len);
    will_return(__wrap_bind, bad_return_value_bind);

#endif

    int ossock = OS_Bindporttcp(test_port, test_ip, test_ipv6);
    assert_int_equal(ossock,err);

}

int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_OS_Bindportudp_success),
        cmocka_unit_test(test_OS_Bindporttcp_success),
        cmocka_unit_test(test_OS_Bindportudp_fail_socket),
        cmocka_unit_test(test_OS_Bindporttcp_fail_socket),
        cmocka_unit_test(test_OS_Bindporttcp_fail_setsockopt),
        cmocka_unit_test(test_OS_Bindporttcp_fail_listen),
        cmocka_unit_test(test_OS_Bindportudp_ipv6_fail_bind),
        cmocka_unit_test(test_OS_Bindportudp_no_ipv6_fail_bind),
        cmocka_unit_test(test_OS_Bindporttcp_ipv6_fail_bind),
        cmocka_unit_test(test_OS_Bindporttcp_no_ipv6_fail_bind)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>

#include "../headers/shared.h"
#include "os_net/os_net.h"
#include "../remoted/remoted.h"

/* private functions to be tested */
int key_request_connect();
int send_key_request(int socket,const char *msg);

/* setup/teardown */
extern remoted logr;

/* redefinitons/wrapping */

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size){
    return mock();
}

int __wrap_OS_SendUnix(int socket, const char *msg, int size){
    return mock();
}

int __wrap_OS_SendSecureTCPCluster(int sock, const void * command, const void * payload, size_t length){
    return mock();
}

int __wrap_OS_RecvSecureClusterTCP(int sock, char * ret, size_t length){
    return mock();
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char *param1;
    char *param2;
    va_list args;
    const char *aux = msg;
    int i = 0;

    va_start(args, msg);

    while(aux = strchr(aux, '%'), aux) {
        i++;
        aux++;
    }

    if(i) {
        param1 = va_arg(args, char*);
        check_expected(param1);
        i--;
    }
    if(i) {
        param2 = va_arg(args, char*);
        check_expected(param2);
    }
    va_end(args);

    check_expected(msg);
    return;
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char *param1;
    char *param2;
    va_list args;
    const char *aux = msg;
    int i = 0;

    va_start(args, msg);

    while(aux = strchr(aux, '%'), aux) {
        i++;
        aux++;
    }

    if(i) {
        param1 = va_arg(args, char*);
        check_expected(param1);
        i--;
    }
    if(i) {
        param2 = va_arg(args, char*);
        check_expected(param2);
    }
    va_end(args);

    check_expected(msg);
    return;
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    char *param1;
    char *param2;
    va_list args;
    const char *aux = msg;
    int i = 0;

    va_start(args, msg);

    while(aux = strchr(aux, '%'), aux) {
        i++;
        aux++;
    }

    if(i) {
        param1 = va_arg(args, char*);
        check_expected(param1);
        i--;
    }
    if(i) {
        param2 = va_arg(args, char*);
        check_expected(param2);
    }
    va_end(args);

    check_expected(msg);
    return;
}

/* tests */

static void test_key_request_connect_enabled_false(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = false;

    will_return(__wrap_OS_ConnectUnixDomain, -1);
    
    ret = key_request_connect();
    
    assert_int_equal(ret, -1);
}

static void test_key_request_connect_local(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = true;
    logr.mode = KEYPOLL_MODE_LOCAL;

    will_return(__wrap_OS_ConnectUnixDomain, 0);
    
    ret = key_request_connect();
    
    assert_int_equal(ret, 0);
}

static void test_key_request_connect_master(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = true;
    logr.mode = KEYPOLL_MODE_MASTER ;

    will_return(__wrap_OS_ConnectUnixDomain, 0);
    
    ret = key_request_connect();
    
    assert_int_equal(ret, 0);
}

static void test_send_key_request_enabled_false(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = false;

    will_return(__wrap_OS_SendUnix, -1);
    
    ret = send_key_request(12,"test_enabled_false");
    
    assert_int_equal(ret, -1);
}

static void test_send_key_request_local(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = true;
    logr.mode = KEYPOLL_MODE_LOCAL;

    will_return(__wrap_OS_SendUnix, 0);
    
    ret = send_key_request(12,"test_local");
    
    assert_int_equal(ret, 0);
}

static void test_send_key_request_master_success(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = true;
    logr.mode = KEYPOLL_MODE_MASTER;

    will_return(__wrap_OS_SendSecureTCPCluster, 1);
    will_return(__wrap_OS_RecvSecureClusterTCP, 1);
    
    expect_string(__wrap__mdebug2, msg, "%s");
    expect_string(__wrap__mdebug2, param1, "");
    
    ret = send_key_request(12,"test_master_success");
    
    assert_int_equal(ret, 1);
}

static void test_send_key_request_recv_msg_less_zero(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = true;
    logr.mode = KEYPOLL_MODE_MASTER;

    will_return(__wrap_OS_SendSecureTCPCluster, -1);
    will_return(__wrap_OS_RecvSecureClusterTCP, -1);
    
    expect_string(__wrap__merror, msg, "No message received from the master.");
    
    ret = send_key_request(12,"test_recv_msg_less_zero");
    
    assert_int_equal(ret, -1);
}

static void test_send_key_request_recv_msg_equal_zero(void **state)
{
    (void) state; /* unused */
    int ret;

    logr.key_polling_enabled = true;
    logr.mode = KEYPOLL_MODE_MASTER;

    will_return(__wrap_OS_SendSecureTCPCluster, 1);
    will_return(__wrap_OS_RecvSecureClusterTCP, 0);
    
    ret = send_key_request(12,"test_recv_msg_equal_zero");
    
    assert_int_equal(ret, OS_SOCKDISCN);
}

int main(void) {
    const struct CMUnitTest tests[] = {           
        //Test key_request_connect
        cmocka_unit_test(test_key_request_connect_enabled_false),
        cmocka_unit_test(test_key_request_connect_local),
        cmocka_unit_test(test_key_request_connect_master),

        //Test send_key_request
        cmocka_unit_test(test_send_key_request_enabled_false),
        cmocka_unit_test(test_send_key_request_local),
        cmocka_unit_test(test_send_key_request_master_success),
        cmocka_unit_test(test_send_key_request_recv_msg_less_zero),
        cmocka_unit_test(test_send_key_request_recv_msg_equal_zero),

    };  
    return cmocka_run_group_tests(tests, NULL, NULL);
}

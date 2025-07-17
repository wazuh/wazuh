/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>
#include <unistd.h>

#include "../headers/shared.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

/* Define values may be changed */

#define MAX_ATTEMPTS 100
#define SOCKET_SIZE 1
#define ERRNO ENOTSOCK

/* Redefinitons/wrapping */

int __wrap_OS_getsocketsize(int ossock) {
    return SOCKET_SIZE;
}

void __wrap_sleep(unsigned int seconds) { };

bool ptr_function_value = false;

bool ptr_function() {
    ptr_function_value = !ptr_function_value;
    return ptr_function_value;
}
/* Tests */

void test_start_mq_read_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = READ;
    char * path = "/test";

    int ret = 0;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, path);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_DGRAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR + 512);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid() );
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, getgid() );
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, 0);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_read_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = READ;
    char * path = "/test";

    int ret = 0;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, path);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_DGRAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR + 512);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, getgid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, -1);

    ret = StartMQ(path, type, n_attempts);
    assert_int_equal(ret, -1);

}

void test_start_mq_write_simple_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 1;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[2][OS_SIZE_64];

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[0], OS_SIZE_64,"Connected succesfully to '%s' after %d attempts", path, 0);
    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    snprintf(messages[1], OS_SIZE_64, "(unix_domain) Maximum send buffer set to: '%d'.",SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_write_simple_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 1;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    errno = ERRNO;

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: 1");

    ret = StartMQ(path, type, n_attempts);
    assert_int_equal(ret, -1);
}

void test_start_mq_write_multiple_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 5;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[n_attempts+1][OS_SIZE_1024];

    errno = ERRNO;

    for (int i = 0; i < n_attempts - 1; i++) {
        expect_string(__wrap_OS_ConnectUnixDomain, path, path);
        expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
        expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        snprintf(messages[i], OS_SIZE_1024, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }
    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[n_attempts - 1], OS_SIZE_1024,"Connected succesfully to '%s' after %d attempts", path, n_attempts - 1);
    expect_string(__wrap__mdebug1, formatted_msg, messages[n_attempts - 1]);

    snprintf(messages[n_attempts], OS_SIZE_1024,"(unix_domain) Maximum send buffer set to: '%d'.", SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[n_attempts]);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_write_multiple_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 10;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[n_attempts][OS_SIZE_1024];

    for (int i = 0; i <= n_attempts - 1; i++) {
        expect_string(__wrap_OS_ConnectUnixDomain, path, path);
        expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
        expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        snprintf(messages[i], OS_SIZE_1024, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }

    ret = StartMQ(path, type, n_attempts);
    assert_int_equal(ret, -1);
}

void test_start_mq_write_inf_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[MAX_ATTEMPTS + 1][OS_SIZE_1024];

    for (int i = 0; i < MAX_ATTEMPTS - 1; i++) {
        expect_string(__wrap_OS_ConnectUnixDomain, path, path);
        expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
        expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        sprintf(messages[i], "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }
    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[MAX_ATTEMPTS - 1], OS_SIZE_1024,"Connected succesfully to '%s' after %d attempts", path, MAX_ATTEMPTS - 1);
    expect_string(__wrap__mdebug1, formatted_msg, messages[MAX_ATTEMPTS - 1]);

    snprintf(messages[MAX_ATTEMPTS], OS_SIZE_1024,"(unix_domain) Maximum send buffer set to: '%d'.", SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[MAX_ATTEMPTS]);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_write_inf_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[MAX_ATTEMPTS][OS_SIZE_1024];

    for (int i = 0; i <= MAX_ATTEMPTS - 1; i++) {
        expect_string(__wrap_OS_ConnectUnixDomain, path, path);
        expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
        expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        snprintf(messages[i], OS_SIZE_1024, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }
    /* Breaking the infinite loop */
    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, 0);
    /* Ignoring output */
    expect_any_count(__wrap__mdebug1, formatted_msg, -1);

    ret = StartMQ(path, type, n_attempts);
}

void test_reconnect_mq_simple_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    char * path = "/test";

    int ret = 0;
    char messages[2][OS_SIZE_64];

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[0], OS_SIZE_64, SUCCESSFULLY_RECONNECTED_SOCKET, path);
    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    snprintf(messages[1], OS_SIZE_64, MSG_SOCKET_SIZE, SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    ret = MQReconnectPredicated(path, &ptr_function);
    assert_false(ret);
}

void test_reconnect_mq_simple_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    char * path = "/test";

    int ret = 0;

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, -1);

    ret = MQReconnectPredicated(path, &ptr_function);
    assert_int_equal(ret, -1);
}

void test_reconnect_mq_complex_true(void ** state){
    (void)state; // Unused __wrap__merror

    /* Function parameters */
    char * path = "/test";
    char * error_message = "Socket operation on non-socket";
    int error_message_id = 88;

    int ret = 0;
    char expected_str[OS_SIZE_128];
    char messages[2][OS_SIZE_128];

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, -1);

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(expected_str, OS_SIZE_128, UNABLE_TO_RECONNECT, path, error_message, error_message_id);
    expect_string(__wrap__merror, formatted_msg, expected_str);

    snprintf(messages[0], OS_SIZE_128, SUCCESSFULLY_RECONNECTED_SOCKET, path);
    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    snprintf(messages[1], OS_SIZE_128, MSG_SOCKET_SIZE, SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    ret = MQReconnectPredicated(path, &ptr_function);
    assert_int_equal(ret, 0);
}

void test_SendMSGAction_format_error(void ** state){
    (void)state;

    expect_string(__wrap__merror, formatted_msg, "(1106): String not correctly formatted.");

    int ret = SendMSG(0, "message", "location", SECURE_MQ);

    assert_int_equal(ret, 0);
}

void test_SendMSGAction_queue_not_available(void ** state){
    (void)state;

    int ret = SendMSG(-1, "message", "location", SYSLOG_MQ);

    assert_int_equal(ret, -1);
}

void test_SendMSGAction_socket_error(void ** state){
    (void)state;
    int queue = 0;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_string(__wrap_OS_SendUnix, msg, "2:location:message");
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "socketerr (not available).");

    int ret = SendMSG(queue, "message", "location", SYSLOG_MQ);

    assert_int_equal(ret, -1);
}

void test_SendMSGAction_socket_busy(void ** state){
    (void)state;
    int queue = 0;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_string(__wrap_OS_SendUnix, msg, "2:location:message");
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, OS_INVALID);

    expect_string(__wrap__mdebug2, formatted_msg, "Socket busy, discarding message.");
    expect_string(__wrap__mwarn, formatted_msg, "Socket busy, discarding message.");

    int ret = SendMSG(queue, "message", "location", SYSLOG_MQ);

    assert_int_equal(ret, 0);
}

void test_SendMSGAction_non_secure_msg(void ** state){
    (void)state;
    int queue = 0;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_string(__wrap_OS_SendUnix, msg, "2:location:message");
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    int ret = SendMSG(queue, "message", "location", SYSLOG_MQ);

    assert_int_equal(ret, 0);
}

void test_SendMSGAction_secure_msg(void ** state){
    (void)state;
    int queue = 0;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_string(__wrap_OS_SendUnix, msg, "4:location->message:");
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    int ret = SendMSG(queue, "4:message:", "location", SECURE_MQ);

    assert_int_equal(ret, 0);
}

void test_SendMSGAction_secure_msg_keepalive(void ** state){
    (void)state;
    int ret = SendMSG(0, "4:keepalive", "location", SECURE_MQ);

    assert_int_equal(ret, 0);
}

void test_SendBinaryMSGAction_secure_mq_not_supported(void **state) {
    (void)state;

    expect_string(__wrap__merror, formatted_msg, "SendBinaryMSGAction does not support SECURE_MQ mode.");

    int ret = SendBinaryMSG(0, "payload", 7, "location", SECURE_MQ);

    assert_int_equal(ret, -1);
}

void test_SendBinaryMSGAction_message_too_large(void **state) {
    (void)state;

    char dummy_payload;
    size_t large_size = OS_MAXSTR;

    expect_any(__wrap__mwarn, formatted_msg);

    int ret = SendBinaryMSG(0, &dummy_payload, large_size, "some_location", 's');

    assert_int_equal(ret, -1);
}

void test_SendBinaryMSGAction_queue_not_available(void **state) {
    (void)state;

    int ret = SendBinaryMSG(-1, "payload", 7, "location", 's');

    assert_int_equal(ret, -1);
}

void test_SendBinaryMSGAction_socket_error(void **state) {
    (void)state;
    int queue = 123;
    const char *payload = "bin_data";
    size_t payload_len = 8;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_any(__wrap_OS_SendUnix, msg);
    expect_value(__wrap_OS_SendUnix, size, 19);
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "socketerr (not available).");

    int ret = SendBinaryMSG(queue, payload, payload_len, "location", 's');

    assert_int_equal(ret, -1);
}

void test_SendBinaryMSGAction_success(void **state) {
    (void)state;
    int queue = 123;
    const char payload[] = {'d', 'a', 't', 'a', '\0', 'm', 'o', 'r', 'e'};
    size_t payload_len = sizeof(payload);
    const char *locmsg = "FIM";
    char loc = 's';

    char expected_msg[100];
    snprintf(expected_msg, sizeof(expected_msg), "%c:%s:", loc, locmsg);
    size_t header_len = strlen(expected_msg);
    memcpy(expected_msg + header_len, payload, payload_len);
    size_t total_len = header_len + payload_len;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_memory(__wrap_OS_SendUnix, msg, expected_msg, total_len);
    expect_value(__wrap_OS_SendUnix, size, total_len);
    will_return(__wrap_OS_SendUnix, 0);

    int ret = SendBinaryMSG(queue, payload, payload_len, locmsg, loc);

    assert_int_equal(ret, 0);
}

void test_SendBinaryMSGAction_socket_busy(void **state) {
    (void)state;
    int queue = 123;
    const char *payload = "data";
    size_t payload_len = 4;
    size_t total_len = strlen("s:loc:") + payload_len;

    expect_value(__wrap_OS_SendUnix, socket, queue);
    expect_any(__wrap_OS_SendUnix, msg);
    expect_value(__wrap_OS_SendUnix, size, total_len);
    will_return(__wrap_OS_SendUnix, OS_INVALID);

    expect_string(__wrap__mdebug2, formatted_msg, "Socket busy, discarding binary message.");
    expect_string(__wrap__mwarn, formatted_msg, "Socket busy, discarding binary message.");

    int ret = SendBinaryMSG(queue, payload, payload_len, "loc", 's');

    assert_int_equal(ret, 0);
}

// Main test function

int main(void){
    const struct CMUnitTest tests[] = {
       cmocka_unit_test(test_start_mq_read_success),
       cmocka_unit_test(test_start_mq_read_fail),
       cmocka_unit_test(test_start_mq_write_simple_success),
       cmocka_unit_test(test_start_mq_write_simple_fail),
       cmocka_unit_test(test_start_mq_write_multiple_success),
       cmocka_unit_test(test_start_mq_write_multiple_fail),
       cmocka_unit_test(test_start_mq_write_inf_success),
       cmocka_unit_test(test_start_mq_write_inf_fail),
       cmocka_unit_test(test_reconnect_mq_simple_fail),
       cmocka_unit_test(test_reconnect_mq_complex_true),
       cmocka_unit_test(test_reconnect_mq_simple_success),
       // Test test_SendMSGAction
       cmocka_unit_test(test_SendMSGAction_format_error),
       cmocka_unit_test(test_SendMSGAction_queue_not_available),
       cmocka_unit_test(test_SendMSGAction_socket_error),
       cmocka_unit_test(test_SendMSGAction_socket_busy),
       cmocka_unit_test(test_SendMSGAction_non_secure_msg),
       cmocka_unit_test(test_SendMSGAction_secure_msg),
       cmocka_unit_test(test_SendMSGAction_secure_msg_keepalive),
       // Test test_SendBinaryMSG
       cmocka_unit_test(test_SendBinaryMSGAction_secure_mq_not_supported),
       cmocka_unit_test(test_SendBinaryMSGAction_message_too_large),
       cmocka_unit_test(test_SendBinaryMSGAction_queue_not_available),
       cmocka_unit_test(test_SendBinaryMSGAction_socket_error),
       cmocka_unit_test(test_SendBinaryMSGAction_success),
       cmocka_unit_test(test_SendBinaryMSGAction_socket_busy),
       };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

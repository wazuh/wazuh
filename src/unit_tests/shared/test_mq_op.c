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

// Longest message to the agent target that is sent. The library is built with CLIENT for the agent tests.
#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
// wazuh-agentd refuses a longer message.
#define MAX_AGENT_MESSAGE (OS_MAXSTR - OS_HEADER_SIZE)
#else
#define MAX_AGENT_MESSAGE (OS_MAXSTR - 1)
#endif

size_t mq_socket_log_size(const char * prefix);

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

static int setup_group(void ** state) {
    (void)state;
    will_return(__wrap_getDefine_Int, 0);
    mq_log_builder_init(false);
    return 0;
}

/* Allocate a string of len bytes, each one taken from chars in turn. */
static char * make_string(size_t len, const char * chars) {
    char * string;
    size_t chars_len = strlen(chars);

    os_malloc(len + 1, string);

    for (size_t i = 0; i < len; i++) {
        string[i] = chars[i % chars_len];
    }

    string[len] = '\0';
    return string;
}

// Last message that OS_SendUnix() got
static char * sent_msg;

static int capture_sent_msg(const LargestIntegralType value, __attribute__((unused)) const LargestIntegralType check_value_data) {
    os_free(sent_msg);
    os_strdup((const char *)(uintptr_t)value, sent_msg);
    return 1;
}

static void expect_OS_SendUnix_capture(int socket, int size) {
    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_check(__wrap_OS_SendUnix, msg, capture_sent_msg, 0);
    expect_value(__wrap_OS_SendUnix, size, size);
    will_return(__wrap_OS_SendUnix, 0);
}

/* Send a log of log_len bytes with the format "[$(log)]end" to a target, and check that the message has the header,
 * the format and as much of the log as fits in max_message bytes. */
static void check_formatted_message(logtarget * target, const char * location, size_t log_len, const char * header, size_t max_message) {
    const char * SUFFIX = "]end";
    const size_t whole_len = strlen(header) + 1 + log_len + strlen(SUFFIX);
    const size_t used_len = whole_len <= max_message ? log_len : log_len - (whole_len - max_message);
    char * log = make_string(log_len, "0123456789");
    int queue = 0;

    target->format = "[$(log)]end";

    if (strcmp(target->log_socket->name, "agent") == 0) {
        expect_OS_SendUnix_capture(queue, 0);
    } else {
        expect_OS_SendUnix_capture(target->log_socket->socket, (int)(whole_len <= max_message ? whole_len : max_message));
    }

    if (used_len < log_len) {
        // The check keeps a pointer to the message.
        static char message[128];
        snprintf(message, sizeof(message), "Log cut from %lu to %lu bytes to fit in its output format.", (unsigned long)log_len, (unsigned long)used_len);
        expect_string(__wrap__mdebug1, formatted_msg, message);
    }

    assert_int_equal(SendMSGtoSCK(queue, log, location, LOCALFILE_MQ, target), 0);

    assert_non_null(sent_msg);
    assert_int_equal(strlen(sent_msg), strlen(header) + 1 + used_len + strlen(SUFFIX));
    assert_true(strlen(sent_msg) <= max_message);
    assert_memory_equal(sent_msg, header, strlen(header));
    assert_int_equal(sent_msg[strlen(header)], '[');
    assert_memory_equal(sent_msg + strlen(header) + 1, log, used_len);
    assert_string_equal(sent_msg + strlen(header) + 1 + used_len, SUFFIX);

    os_free(sent_msg);
    free(log);
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

void test_start_mq_predicated_write_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
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

    ret = StartMQPredicated(path, type, n_attempts, ptr_function);
    assert_false(ret);
}

void test_start_mq_predicated_write_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    errno = ERRNO;

    expect_string(__wrap_OS_ConnectUnixDomain, path, path);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, -1);
    expect_string(__wrap__mdebug2, formatted_msg, "(6220): Reconnection attempts terminated due to the shutdown of FIM.");

    ret = StartMQPredicated(path, type, n_attempts, ptr_function);
    assert_int_equal(ret, -1);
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
    expect_string(__wrap__mdebug1, formatted_msg, expected_str);

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

    expect_string(__wrap__mdebug1, formatted_msg, "socketerr (not available).");

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

// The first send fails on a connected socket, so SendMSGtoSCK() closes it and connects again
static void expect_SendMSGtoSCK_reconnection(socket_forwarder * forwarder, int new_socket) {
    expect_OS_SendUnix_call(forwarder->socket, "message", strlen("message"), OS_SOCKTERR);

    expect_string(__wrap_OS_ConnectUnixDomain, path, forwarder->location);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, new_socket);

    if (new_socket >= 0) {
        expect_string(__wrap__mdebug1, formatted_msg, "Connected to socket 'test' (/test/socket)");
    }
}

void test_SendMSGtoSCK_retry_success(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "test", .location = "/test/socket", .mode = IPPROTO_UDP,
                                   .socket = socket(AF_UNIX, SOCK_DGRAM, 0), .last_attempt = 0 };
    logtarget target = { .format = NULL, .log_socket = &forwarder };

    assert_true(forwarder.socket >= 0);
    sock_fail_time = 300;

    expect_SendMSGtoSCK_reconnection(&forwarder, 1000);
    expect_OS_SendUnix_call(1000, "message", strlen("message"), 0);

    int ret = SendMSGtoSCK(0, "message", "location", LOCALFILE_MQ, &target);

    assert_int_equal(ret, 0);
    assert_int_equal(forwarder.socket, 1000);
    assert_int_equal(forwarder.last_attempt, 0);
}

void test_SendMSGtoSCK_retry_fail(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "test", .location = "/test/socket", .mode = IPPROTO_UDP,
                                   .socket = socket(AF_UNIX, SOCK_DGRAM, 0), .last_attempt = 0 };
    logtarget target = { .format = NULL, .log_socket = &forwarder };

    assert_true(forwarder.socket >= 0);
    sock_fail_time = 300;

    expect_SendMSGtoSCK_reconnection(&forwarder, 1000);
    expect_OS_SendUnix_call(1000, "message", strlen("message"), OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "Cannot send message to socket 'test'. (Retry)");
    expect_OS_SendUnix_call(0, "1:logcollector:Cannot send message to socket.", 0, 0);

    int ret = SendMSGtoSCK(0, "message", "location", LOCALFILE_MQ, &target);

    assert_int_equal(ret, 1);
    assert_int_not_equal(forwarder.last_attempt, 0);
}

void test_SendMSGtoSCK_reconnect_fail(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "test", .location = "/test/socket", .mode = IPPROTO_UDP,
                                   .socket = socket(AF_UNIX, SOCK_DGRAM, 0), .last_attempt = 0 };
    logtarget target = { .format = NULL, .log_socket = &forwarder };

    assert_true(forwarder.socket >= 0);
    sock_fail_time = 300;

    expect_SendMSGtoSCK_reconnection(&forwarder, -1);
    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket 'test': /test/socket (udp)");

    int ret = SendMSGtoSCK(0, "message", "location", LOCALFILE_MQ, &target);

    assert_int_equal(ret, 1);
    assert_int_equal(forwarder.socket, -1);
    assert_int_not_equal(forwarder.last_attempt, 0);
}

// The last failed connection is too recent to reconnect, so the message is discarded
void test_SendMSGtoSCK_reconnect_wait(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "test", .location = "/test/socket", .mode = IPPROTO_UDP,
                                   .socket = socket(AF_UNIX, SOCK_DGRAM, 0), .last_attempt = time(NULL) };
    logtarget target = { .format = NULL, .log_socket = &forwarder };
    const int fd = forwarder.socket;

    assert_true(fd >= 0);
    sock_fail_time = 300;

    expect_OS_SendUnix_call(fd, "message", strlen("message"), OS_SOCKTERR);
    expect_string(__wrap__mdebug2, formatted_msg, "Discarding event from 'location' due to connection issue with 'test'");

    int ret = SendMSGtoSCK(0, "message", "location", LOCALFILE_MQ, &target);

    assert_int_equal(ret, 1);
    assert_int_equal(forwarder.socket, fd);
    close(fd);
}

void test_SendMSGtoSCK_socket_busy(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "test", .location = "/test/socket", .mode = IPPROTO_UDP,
                                   .socket = socket(AF_UNIX, SOCK_DGRAM, 0), .last_attempt = 0 };
    logtarget target = { .format = NULL, .log_socket = &forwarder };
    const int fd = forwarder.socket;

    assert_true(fd >= 0);
    sock_fail_time = 300;

    expect_OS_SendUnix_call(fd, "message", strlen("message"), OS_SOCKBUSY);
    expect_string(__wrap__merror, formatted_msg, "Cannot send message to socket 'test'. (Retry)");
    expect_OS_SendUnix_call(0, "1:logcollector:Cannot send message to socket.", 0, 0);

    int ret = SendMSGtoSCK(0, "message", "location", LOCALFILE_MQ, &target);

    assert_int_equal(ret, 1);
    assert_int_equal(forwarder.socket, fd);
    close(fd);
}

// A formatted log to the agent target fits in the message that is sent, and is cut no more than needed.
void test_SendMSGtoSCK_agent_log_fits_message(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "agent", .socket = -1 };
    logtarget target = { .log_socket = &forwarder };
    const char * HEADER = "1:/var/log/syslog:";
    // Length of the log that fills the message
    const size_t FULL = MAX_AGENT_MESSAGE - strlen(HEADER) - strlen("[]end");

    check_formatted_message(&target, "/var/log/syslog", FULL, HEADER, MAX_AGENT_MESSAGE);
    check_formatted_message(&target, "/var/log/syslog", FULL + 1, HEADER, MAX_AGENT_MESSAGE);
    check_formatted_message(&target, "/var/log/syslog", OS_MAXSTR, HEADER, MAX_AGENT_MESSAGE);
}

// The cut leaves room for a long location, after ':' and '|' are escaped in it and it is cut at OS_SIZE_8192 bytes.
void test_SendMSGtoSCK_agent_long_location(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "agent", .socket = -1 };
    logtarget target = { .log_socket = &forwarder };
    char loc_buff[OS_SIZE_8192 + 1];
    char header[OS_SIZE_8192 + 4];
    char * location;

    location = make_string(2000, "C:\\logs|app");
    assert_int_equal(wstr_escape(loc_buff, sizeof(loc_buff), location, '|', ':'), 2000 + 2000 / 11 * 2 + 2);
    snprintf(header, sizeof(header), "1:%s:", loc_buff);
    check_formatted_message(&target, location, OS_MAXSTR, header, MAX_AGENT_MESSAGE);
    free(location);

    location = make_string(OS_SIZE_8192 + 1000, "/var/log/app");
    assert_int_equal(wstr_escape(loc_buff, sizeof(loc_buff), location, '|', ':'), OS_SIZE_8192);
    snprintf(header, sizeof(header), "1:%s:", loc_buff);
    check_formatted_message(&target, location, OS_MAXSTR, header, MAX_AGENT_MESSAGE);
    free(location);
}

// A socket target gets its prefix before the log and no location, so the cut leaves room only for the prefix.
void test_SendMSGtoSCK_socket_log_fits_message(void ** state) {
    (void)state;
    socket_forwarder forwarder = { .name = "test", .location = "/test/socket", .mode = IPPROTO_UDP, .socket = 1000 };
    logtarget target = { .log_socket = &forwarder };
    char * location = make_string(600, "/var/log/app");
    char * prefix;

    // No prefix
    check_formatted_message(&target, location, OS_MAXSTR - 1 - strlen("[]end"), "", OS_MAXSTR - 1);
    check_formatted_message(&target, location, OS_MAXSTR, "", OS_MAXSTR - 1);

    // Short prefix
    forwarder.prefix = "prefix: ";
    check_formatted_message(&target, location, OS_MAXSTR, "prefix: ", OS_MAXSTR - 1);

    // Prefix longer than OS_LOG_HEADER bytes
    prefix = make_string(1000, "p");
    forwarder.prefix = prefix;
    check_formatted_message(&target, location, OS_MAXSTR, prefix, OS_MAXSTR - 1);

    free(prefix);
    free(location);
}

void test_mq_socket_log_size(void ** state) {
    (void)state;
    char * prefix;

    assert_int_equal(mq_socket_log_size(NULL), OS_MAXSTR);
    assert_int_equal(mq_socket_log_size(""), OS_MAXSTR);
    assert_int_equal(mq_socket_log_size("prefix: "), OS_MAXSTR - strlen("prefix: "));

    // A prefix that leaves room for one byte of the log, and longer ones
    prefix = make_string(OS_MAXSTR - 2, "p");
    assert_int_equal(mq_socket_log_size(prefix), 2);
    free(prefix);

    prefix = make_string(OS_MAXSTR - 1, "p");
    assert_int_equal(mq_socket_log_size(prefix), 1);
    free(prefix);

    prefix = make_string(OS_MAXSTR + 10, "p");
    assert_int_equal(mq_socket_log_size(prefix), 1);
    free(prefix);
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
       cmocka_unit_test(test_start_mq_predicated_write_success),
       cmocka_unit_test(test_start_mq_predicated_write_fail),
       // Test test_SendMSGAction
       cmocka_unit_test(test_SendMSGAction_format_error),
       cmocka_unit_test(test_SendMSGAction_queue_not_available),
       cmocka_unit_test(test_SendMSGAction_socket_error),
       cmocka_unit_test(test_SendMSGAction_socket_busy),
       cmocka_unit_test(test_SendMSGAction_non_secure_msg),
       cmocka_unit_test(test_SendMSGAction_secure_msg),
       cmocka_unit_test(test_SendMSGAction_secure_msg_keepalive),
       // Test SendMSGtoSCK
       cmocka_unit_test(test_SendMSGtoSCK_retry_success),
       cmocka_unit_test(test_SendMSGtoSCK_retry_fail),
       cmocka_unit_test(test_SendMSGtoSCK_reconnect_fail),
       cmocka_unit_test(test_SendMSGtoSCK_reconnect_wait),
       cmocka_unit_test(test_SendMSGtoSCK_socket_busy),
       cmocka_unit_test(test_SendMSGtoSCK_agent_log_fits_message),
       cmocka_unit_test(test_SendMSGtoSCK_agent_long_location),
       cmocka_unit_test(test_SendMSGtoSCK_socket_log_fits_message),
       cmocka_unit_test(test_mq_socket_log_size),
       };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}

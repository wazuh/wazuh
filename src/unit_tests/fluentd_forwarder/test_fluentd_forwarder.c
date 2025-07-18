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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/wm_fluent.h"
#include "../../wazuh_modules/wm_fluent.c"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

typedef struct test_struct {
    wm_fluent_t *fluent;
    cJSON * configuration_dump;
} test_struct_t;

#define SOCKET_PATH "/tmp/socket-tmp"

time_t __wrap_time(int time) {
    check_expected(time);
    return mock();
}

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1, sizeof(wm_fluent_t), init_data->fluent);

    *state = init_data;
    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    if(data->configuration_dump) {
        cJSON_Delete(data->configuration_dump);
    }
    os_free(data->fluent);
    os_free(data);

    return OS_SUCCESS;
}

void assert_int_lt(int X, int Y) {
    if (X < Y) {
        assert_true(true);
    } else {
        assert_false(false);
    }
}

void assert_int_ge(int X, int Y) {
    if (X >= Y) {
        assert_true(true);
    } else {
        assert_false(false);
    }
}

// Tests
void test_check_config_no_tag(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_string(__wrap__mterror, formatted_msg, "No tag defined.");

    data->fluent->tag = NULL;
    assert_int_lt(wm_fluent_check_config(data->fluent), 0);
}

void test_check_config_no_socket(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_string(__wrap__mterror, formatted_msg, "No socket_path defined.");

    data->fluent->tag = "debug.test";
    assert_int_lt(wm_fluent_check_config(data->fluent), 0);
}

void test_check_config_no_address(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mtinfo, tag, "fluent-forward");
    expect_string(__wrap__mtinfo, formatted_msg, "No client address defined. Using localhost.");

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/socket.s";
    int simple_configuration_no_address = wm_fluent_check_config(data->fluent);
    os_free(data->fluent->address);
    assert_int_equal(simple_configuration_no_address, 0);
}

void test_check_config_invalid_timeout(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->timeout = -1;

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_string(__wrap__mterror, formatted_msg, "Invalid timeout value (negative)");

    assert_int_lt(wm_fluent_check_config(data->fluent), 0);
}

void test_check_config_no_password(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->timeout = 0;
    data->fluent->user_name = "user";

    expect_string(__wrap__mtwarn, tag, "fluent-forward");
    expect_string(__wrap__mtwarn, formatted_msg, "No shared_key defined. SSL is disabled and the user_name option won't apply.");

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_string(__wrap__mterror, formatted_msg, "Password required because user_name is defined");

    assert_int_lt(wm_fluent_check_config(data->fluent), 0);
}

void test_check_valid_config_tls(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->certificate = "test.pem";
    data->fluent->shared_key = "secret_key";
    data->fluent->user_name = "foo";
    data->fluent->user_pass = "bar";
    data->fluent->timeout = 0;
    int simple_configuration_no_password = wm_fluent_check_config(data->fluent);

    assert_int_equal(simple_configuration_no_password, 0);
}

void test_check_config_dump(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->timeout = 0;
    data->fluent->user_name = "user";
    data->fluent->user_pass = "bar";
    data->fluent->shared_key = "secret_key";
    data->fluent->timeout = 100;
    data->fluent->port = 24224;
    data->configuration_dump = wm_fluent_dump(data->fluent);

    assert_non_null(data->configuration_dump);
}

void test_check_default_connection(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->port = 24224;
    data->fluent->timeout = 0;

    expect_any(__wrap__mtdebug2, tag);
    expect_any(__wrap__mtdebug2, formatted_msg);

    expect_any(__wrap_OS_GetHost, host);
    will_return(__wrap_OS_GetHost, strdup("localhost"));

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 1);

    int simple_configuration_defaut_connection = wm_fluent_connect(data->fluent);

    assert_int_equal(simple_configuration_defaut_connection, 0);
}

void test_check_default_handshake(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->port = 24224;
    data->fluent->timeout = 0;

    expect_string(__wrap__mtinfo, tag, "fluent-forward");
    expect_string(__wrap__mtinfo, formatted_msg, "Connected to host localhost:24224");

    expect_any(__wrap__mtdebug2, tag);
    expect_any(__wrap__mtdebug2, formatted_msg);

    expect_any(__wrap_OS_GetHost, host);
    will_return(__wrap_OS_GetHost, strdup("localhost"));

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 1);

    int simple_configuration_defaut_handshake = wm_fluent_handshake(data->fluent);
    assert_int_equal(simple_configuration_defaut_handshake, 0);
}

void test_check_send(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->fluent->tag = "debug.test";
    data->fluent->sock_path = "/var/run/fluent-socket";
    data->fluent->address = "localhost";
    data->fluent->port = 24224;
    data->fluent->timeout = 0;
    data->fluent->object_key = "message";

    expect_string(__wrap__mtinfo, tag, "fluent-forward");
    expect_string(__wrap__mtinfo, formatted_msg, "Connected to host localhost:24224");

    expect_any(__wrap__mtdebug2, tag);
    expect_any(__wrap__mtdebug2, formatted_msg);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 165884);

    expect_any(__wrap_OS_GetHost, host);
    will_return(__wrap_OS_GetHost, strdup("localhost"));

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 1);

    int simple_configuration_defaut_handshake = wm_fluent_handshake(data->fluent);
    assert_int_equal(simple_configuration_defaut_handshake, 0);

    char *msg = "{\"json\":\"message\"}";
    assert_int_ge(wm_fluent_send(data->fluent, msg, strlen(msg)), 0);
}

void test_send_json_message_success_udp(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = -1;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, fdsock);

    expect_value(__wrap_OS_SendUnix, socket, fdsock);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, 1);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 165884);
    expect_string_count(__wrap__mdebug1, formatted_msg, "Connected to socket 'fluentd_test' (/tmp/socket-tmp)",1);

    expect_string_count(__wrap__mdebug2, formatted_msg, "Message send to socket 'fluentd_test' (/tmp/socket-tmp) successfully.",1);

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_success_udp_again(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = -1;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 165884);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, fdsock);

    expect_string(__wrap__mdebug1, formatted_msg, "Connected to socket 'fluentd_test' (/tmp/socket-tmp)");

    expect_value(__wrap_OS_SendUnix, socket, fdsock);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 165884);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, fdsock);

    expect_string(__wrap__mdebug1, formatted_msg, "Connected to socket 'fluentd_test' (/tmp/socket-tmp)");

    expect_value(__wrap_OS_SendUnix, socket, fdsock);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, 1);

    expect_string_count(__wrap__mdebug2, formatted_msg, "Message send to socket 'fluentd_test' (/tmp/socket-tmp) successfully.",1);

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_success_tcp(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_TCP;
    socket_info->socket = -1;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_STREAM, OS_MAXSTR);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, fdsock);

    expect_value(__wrap_OS_SendUnix, socket, fdsock);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, 1);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 165884);

    expect_string_count(__wrap__mdebug1, formatted_msg, "Connected to socket 'fluentd_test' (/tmp/socket-tmp)",1);

    expect_string_count(__wrap__mdebug2, formatted_msg, "Message send to socket 'fluentd_test' (/tmp/socket-tmp) successfully.",1);

    int ret = SendJSONtoSCK(json_msg,socket_info);

    assert_return_code(ret,1);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_invalid_socket(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = 0;
    socket_info->socket = -1;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_any(__wrap__merror,formatted_msg);

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_null(void **state) {

    socket_forwarder* socket_info = NULL;
    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_any(__wrap__merror,formatted_msg);

    SendJSONtoSCK(json_msg,socket_info);

    os_free(json_msg);
    unlink(SOCKET_PATH);
}

void test_send_json_message_socket_error(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = fdsock;

    errno=ENOBUFS;

    expect_value(__wrap_OS_SendUnix, socket, fdsock);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, OS_SOCKBUSY);

    expect_string(__wrap__mdebug2, formatted_msg, "Cannot send message to socket 'fluentd_test' due No buffer space available. (Abort).");

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_socket_error_connect(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = 0;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_value(__wrap_OS_SendUnix, socket, 0);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 1655884);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, fdsock);

    expect_value(__wrap_OS_SendUnix, socket, fdsock);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_string(__wrap__mdebug1, formatted_msg, "Connected to socket 'fluentd_test' (/tmp/socket-tmp)");

    expect_string(__wrap__mdebug2, formatted_msg, "Cannot send message to socket 'fluentd_test' due No such file or directory. (Abort).");

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_socket_error_time(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = -1;
    socket_info->last_attempt = 208354995;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "Discarding event '{\"info\":\"test\"}' due to connection issue with 'fluentd_test'");

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_socket_error_time_again(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = 0;
    socket_info->last_attempt = 208354995;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_value(__wrap_OS_SendUnix, socket, 0);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "Discarding event from engine due to connection issue with 'fluentd_test', No such file or directory. (Abort).");

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_socket_error_unable_connect(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = -1;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, -1);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 1);
    expect_any(__wrap__merror,formatted_msg);

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

void test_send_json_message_socket_error_unable_connect_again(void **state) {

    socket_forwarder* socket_info;

    os_calloc(1,sizeof(socket_forwarder),socket_info);

    static const int fdsock = 65555;
    char* json_msg = strdup("{\"info\":\"test\"}");

    socket_info->name = "fluentd_test";
    socket_info->location = SOCKET_PATH;
    socket_info->mode = IPPROTO_UDP;
    socket_info->socket = 0;

    OS_BindUnixDomain(SOCKET_PATH, SOCK_DGRAM, OS_MAXSTR);

    expect_value(__wrap_OS_SendUnix, socket, 0);
    expect_string(__wrap_OS_SendUnix, msg, json_msg);
    expect_value(__wrap_OS_SendUnix, size, strlen(json_msg));
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, 165884);

    expect_string(__wrap_OS_ConnectUnixDomain, path, SOCKET_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_DGRAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR + 256);
    will_return(__wrap_OS_ConnectUnixDomain, -1);

    expect_any(__wrap__merror,formatted_msg);

    SendJSONtoSCK(json_msg,socket_info);

    os_free(socket_info);
    unlink(SOCKET_PATH);
}

int main(void) {
    const struct CMUnitTest tests[] = {

    /* Simple configuration, no tag defined */
    cmocka_unit_test_setup_teardown(test_check_config_no_tag, test_setup, test_teardown),

    /* Simple configuration, no socket_path defined */
    cmocka_unit_test_setup_teardown(test_check_config_no_socket, test_setup, test_teardown),

    /* Simple configuration, no address defined */
    cmocka_unit_test_setup_teardown(test_check_config_no_address, test_setup, test_teardown),

    /* Simple configuration, invalid timeout defined */
    cmocka_unit_test_setup_teardown(test_check_config_invalid_timeout, test_setup, test_teardown),

    /* Simple configuration, no password defined */
    cmocka_unit_test_setup_teardown(test_check_config_no_password, test_setup, test_teardown),

    /* Simple configuration, TLS valid */
    cmocka_unit_test_setup_teardown(test_check_valid_config_tls, test_setup, test_teardown),

    /* Test connection todata->fluentd server, no TLS */
    cmocka_unit_test_setup_teardown(test_check_default_connection, test_setup, test_teardown),

    /* Test handshake todata->fluentd server, no TLS */
    cmocka_unit_test_setup_teardown(test_check_default_handshake, test_setup, test_teardown),

    /* Test send todata->fluentd server, no TLS */
    cmocka_unit_test_setup_teardown(test_check_send, test_setup, test_teardown),

    /* Test configuration dump*/
    cmocka_unit_test_setup_teardown(test_check_config_dump, test_setup, test_teardown),

    /* Test send JSON using unix socket UDP*/
    cmocka_unit_test_setup_teardown(test_send_json_message_success_udp, test_setup, test_teardown),
    /* Test send in second try JSON using unix socket UDP*/
    cmocka_unit_test_setup_teardown(test_send_json_message_success_udp_again, test_setup, test_teardown),
    /* Test send JSON using unix socket TCP*/
    cmocka_unit_test_setup_teardown(test_send_json_message_success_tcp, test_setup, test_teardown),
    /* Test send JSON using NULL socket*/
    cmocka_unit_test_setup_teardown(test_send_json_message_invalid_socket, test_setup, test_teardown),
    /* Test send NULL object*/
    cmocka_unit_test_setup_teardown(test_send_json_message_null, test_setup, test_teardown),
    /* Test no listener*/
    cmocka_unit_test_setup_teardown(test_send_json_message_socket_error, test_setup, test_teardown),
    /* Test wrong socket*/
    cmocka_unit_test_setup_teardown(test_send_json_message_socket_error_connect, test_setup, test_teardown),
    /* Test time out */
    cmocka_unit_test_setup_teardown(test_send_json_message_socket_error_time, test_setup, test_teardown),
    /* Test time out second time*/
    cmocka_unit_test_setup_teardown(test_send_json_message_socket_error_time_again, test_setup, test_teardown),
    /* Test unable to connect with socket */
    cmocka_unit_test_setup_teardown(test_send_json_message_socket_error_unable_connect, test_setup, test_teardown),
    /* Test unable to connect with socket in second try */
    cmocka_unit_test_setup_teardown(test_send_json_message_socket_error_unable_connect_again, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

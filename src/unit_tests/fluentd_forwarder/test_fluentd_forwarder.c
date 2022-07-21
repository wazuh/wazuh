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

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 1);

    int simple_configuration_defaut_handshake = wm_fluent_handshake(data->fluent);
    assert_int_equal(simple_configuration_defaut_handshake, 0);

    char *msg = "{\"json\":\"message\"}";
    assert_int_ge(wm_fluent_send(data->fluent, msg, strlen(msg)), 0);
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../wazuh_modules/wmodules.h"
#include "../wazuh_modules/wm_fluent.h"
#include "../wazuh_modules/wm_fluent.c"

#include "tap.h"

int test_check_config_no_tag(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = NULL;

    int simple_configuration_no_tag;
    w_assert_int_lt((simple_configuration_no_tag = wm_fluent_check_config(fluent)), 0);
    os_free(fluent);

    return 1;
}

int test_check_config_no_socket(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    int simple_configuration_no_socket;

    w_assert_int_lt((simple_configuration_no_socket = wm_fluent_check_config(fluent)), 0);
    os_free(fluent);

    return 1;
}

int test_check_config_no_address(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/socket.s";
    int simple_configuration_no_address;

    w_assert_int_eq((simple_configuration_no_address = wm_fluent_check_config(fluent)), 0);
    os_free(fluent->address);
    os_free(fluent);

    return 1;
}

int test_check_config_invalid_timeout(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->timeout = -1;
    int simple_configuration_invalid_timeout;

    w_assert_int_lt((simple_configuration_invalid_timeout = wm_fluent_check_config(fluent)), 0);
    os_free(fluent);

    return 1;
}

int test_check_config_no_password(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->timeout = 0;
    fluent->user_name = "user";
    int simple_configuration_no_password;

    w_assert_int_lt((simple_configuration_no_password = wm_fluent_check_config(fluent)), 0);
    os_free(fluent);

    return 1;
}

int test_check_valid_config_tls(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->certificate = "test.pem";
    fluent->shared_key = "secret_key";
    fluent->user_name = "foo";
    fluent->user_pass = "bar";
    fluent->timeout = 0;
    int simple_configuration_no_password;

    w_assert_int_eq((simple_configuration_no_password = wm_fluent_check_config(fluent)), 0);
    os_free(fluent);

    return 1;
}

int test_check_config_dump(){
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->timeout = 0;
    fluent->user_name = "user";
    fluent->user_pass = "bar";
    fluent->shared_key = "secret_key";
    fluent->timeout = 100;
    fluent->port = 24224;
    cJSON * configuration_dump;

    w_assert_ptr_ne((configuration_dump = wm_fluent_dump(fluent)), NULL);
    os_free(fluent);
    cJSON_Delete(configuration_dump);

    return 1;
}


int test_check_default_connection() {
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->port = 24224;
    fluent->timeout = 0;
    int simple_configuration_defaut_connection;

    w_assert_int_eq((simple_configuration_defaut_connection = wm_fluent_connect(fluent)), 0);
    os_free(fluent);

    return 1;
}

int test_check_default_handshake() {
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->port = 24224;
    fluent->timeout = 0;
    int simple_configuration_defaut_handshake;

    w_assert_int_eq((simple_configuration_defaut_handshake = wm_fluent_handshake(fluent)), 0);

    os_free(fluent);

    return 1;
}

int test_check_send() {
    wm_fluent_t * fluent;
    os_calloc(1, sizeof(wm_fluent_t), fluent);
    fluent->tag = "debug.test";
    fluent->sock_path = "/var/run/fluent-socket";
    fluent->address = "localhost";
    fluent->port = 24224;
    fluent->timeout = 0;
    int simple_configuration_defaut_handshake;
    int simple_configuration_send;

    w_assert_int_eq((simple_configuration_defaut_handshake = wm_fluent_handshake(fluent)), 0);

    char *msg = "{\"json\":\"message\"}";
    w_assert_int_ge((simple_configuration_send = wm_fluent_send(fluent,msg,strlen(msg))), 0);

    os_free(fluent);

    return 1;
}


int main(void) {
    printf("\n\n   STARTING TEST - FLUENTD FORWARDER MODULE  \n\n");

    /* Simple configuration, no tag defined */
    TAP_TEST_MSG(test_check_config_no_tag(), "Test configuration no 'tag' defined.");

    /* Simple configuration, no socket_path defined */
    TAP_TEST_MSG(test_check_config_no_socket(), "Test configuration no 'socket_path' defined.");

    /* Simple configuration, no address defined */
    TAP_TEST_MSG(test_check_config_no_address(), "Test configuration no 'address' defined.");

    /* Simple configuration, invalid timeout defined */
    TAP_TEST_MSG(test_check_config_invalid_timeout(), "Test configuration invalid 'timeout' defined.");

    /* Simple configuration, no password defined */
    TAP_TEST_MSG(test_check_config_no_password(), "Test configuration no 'password' defined.");

    /* Simple configuration, TLS valid */
    TAP_TEST_MSG(test_check_valid_config_tls(), "Test configuration valid configuration");

    /* Test connection to Fluentd server, no TLS */
    TAP_TEST_MSG(test_check_default_connection(), "Test connection");

    /* Test handshake to Fluentd server, no TLS */
    TAP_TEST_MSG(test_check_default_handshake(), "Test handshake");

    /* Test send to Fluentd server, no TLS */
    TAP_TEST_MSG(test_check_send(), "Test send message");

    /* Test configuration dump*/
    TAP_TEST_MSG(test_check_config_dump(), "Test configuration dump");

    TAP_PLAN;
    int r = tap_summary();
    printf("\n   ENDING TEST  - FLUENTD FORWARDER MODULE   \n\n");
    return r;
}

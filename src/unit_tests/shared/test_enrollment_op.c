#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "../os_auth/check_cert.h"
#include "../os_auth/auth.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/externals/openssl/bio_wrappers.h"
#include "../wrappers/externals/openssl/ssl_lib_wrappers.h"
#include "../wrappers/wazuh/os_auth/os_auth_wrappers.h"

#define NEW_AGENT1      "Agent1"
#define AGENT1_ID       "001"
#define NEW_IP1         "192.0.0.0"
#define RAW_KEY         "6dd186d1740f6c80d4d380ebe72c8061db175881e07e809eb44404c836a7ef96"

extern int w_enrollment_concat_src_ip(char *buff, const size_t remain_size, const char* sender_ip, const int use_src_ip);
extern void w_enrollment_concat_group(char *buff, const char* centralized_group);
extern void w_enrollment_concat_key(char *buff, keyentry* key_entry);
extern int w_enrollment_verify_ca_certificate(const SSL *ssl, const char *ca_cert, const char *hostname);
extern int w_enrollment_connect(w_enrollment_ctx *cfg, const char * server_address, uint32_t network_interface);
extern int w_enrollment_send_message(w_enrollment_ctx *cfg);
extern int w_enrollment_store_key_entry(const char* keys);
extern int w_enrollment_process_agent_key(char *buffer);
extern int w_enrollment_process_response(SSL *ssl);
extern char *w_enrollment_extract_agent_name(const w_enrollment_ctx *cfg);
extern void w_enrollment_load_pass(w_enrollment_cert *cert_cfg);

/*************** WRAPS ************************/

extern SSL *__real_SSL_new(SSL_CTX *ctx);

int __wrap_TempFile(File *file, const char *source, int copy) {
    file->name = mock_type(char *);
    file->fp = mock_type(FILE *);
    check_expected(source);
    check_expected(copy);
    return mock_type(int);
}

void keyentry_init (keyentry *key, char *name, char *id, char *ip, char *raw_key) {
    os_calloc(1, sizeof(os_ip), key->ip);
    key->ip->ip = ip ? strdup(ip) : NULL;
    key->name = name ? strdup(name) : NULL;
    key->id = id ? strdup(id) : NULL;
    key->raw_key = raw_key ? strdup(raw_key) : NULL;
}

void free_keyentry (keyentry *key) {
    os_free(key->ip->ip);
    os_free(key->ip);
    os_free(key->name);
    os_free(key->id);
    os_free(key->raw_key);
}

// Setup / Teardown global
int setup_file_ops(void **state) {
    test_mode = 1;
    return 0;
}

int teardown_file_ops(void **state) {
    test_mode = 0;
    return 0;
}

// Setup
int test_setup_concats(void **state) {
    char *buf;
    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';
    *state = buf;
    return 0;
}

int test_setup_concats_small_buff(void **state) {
    char *buf;
    os_calloc(30, sizeof(char), buf);
    buf[29] = '\0';
    *state = buf;
    return 0;
}

//Teardown
int test_teardown_concats(void **state) {
    free(*state);
    return 0;
}

// Setup
int test_setup_context(void **state) {
    w_enrollment_target* local_target;
    local_target = w_enrollment_target_init();
    local_target->manager_name = strdup("valid_hostname");
    local_target->agent_name = NULL;
    local_target->sender_ip = NULL;
    local_target->port = 1234;
    local_target->centralized_group = NULL;
    w_enrollment_cert* local_cert;
    local_cert = w_enrollment_cert_init();
    local_cert->agent_cert = strdup("CERT");
    local_cert->agent_key = strdup("KEY");
    local_cert->ca_cert = strdup("CA_CERT");
    // Keys initialization
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keysize = 0;
    w_enrollment_ctx *cfg = w_enrollment_init(local_target, local_cert, keys);
    *state = cfg;
    return 0;
}

//Teardown
int test_teardown_context(void **state) {
    w_enrollment_ctx *cfg = *state;
    os_free(cfg->target_cfg->manager_name);
    os_free(cfg->target_cfg->centralized_group);
    os_free(cfg->target_cfg->agent_name);
    os_free(cfg->target_cfg->sender_ip);
    os_free(cfg->target_cfg);
    w_enrollment_cert_destroy(cfg->cert_cfg);
    os_free(cfg->keys);
    if(cfg->ssl) {
        SSL_free(cfg->ssl);
    }
    w_enrollment_destroy(cfg);
    return 0;
}

//Setup
int test_setup_context_2(void **state) {
    w_enrollment_target* local_target;
    local_target = w_enrollment_target_init();
    local_target->manager_name = strdup("valid_hostname");
    local_target->agent_name = strdup("test_agent");
    local_target->sender_ip = strdup("192.168.1.1");
    local_target->port = 1234;
    local_target->centralized_group = strdup("test_group");
    w_enrollment_cert* local_cert;
    local_cert = w_enrollment_cert_init();
    local_cert->authpass = strdup("test_password");
    local_cert->agent_cert = strdup("CERT");
    local_cert->agent_key = strdup("KEY");
    local_cert->ca_cert = strdup("CA_CERT");
    // Keys initialization
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keysize = 0;
    w_enrollment_ctx *cfg = w_enrollment_init(local_target, local_cert, keys);
    *state = cfg;
    return 0;
}

//Setup
int test_setup_context_3(void **state) {
    w_enrollment_target* local_target;
    local_target = w_enrollment_target_init();
    local_target->manager_name = strdup("valid_hostname");
    local_target->agent_name = strdup("Invalid\'!@Hostname\'");
    local_target->sender_ip = NULL;
    local_target->port = 1234;
    local_target->centralized_group = NULL;
    w_enrollment_cert* local_cert;
    local_cert = w_enrollment_cert_init();
    local_cert->agent_cert = strdup("CERT");
    local_cert->agent_key = strdup("KEY");
    local_cert->ca_cert = strdup("CA_CERT");
    // Keys initialization
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keysize = 0;
    w_enrollment_ctx *cfg = w_enrollment_init(local_target, local_cert, keys);
    *state = cfg;
    return 0;
}

//Setup
int test_setup_w_enrollment_request_key(void **state) {
    w_enrollment_target* local_target;
    local_target = w_enrollment_target_init();
    local_target->manager_name = strdup("valid_hostname");
    local_target->agent_name = strdup("test_agent");
    local_target->sender_ip = strdup("192.168.1.1");
    local_target->port = 1234;
    local_target->centralized_group = strdup("test_group");
    w_enrollment_cert* local_cert;
    local_cert = w_enrollment_cert_init();
    local_cert->auto_method = 0;
    local_cert->authpass = strdup("test_password");
    local_cert->agent_cert = strdup("CERT");
    local_cert->agent_key = strdup("KEY");
    local_cert->ca_cert = strdup("CA_CERT");
    // Keys initialization
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keysize = 0;
    w_enrollment_ctx *cfg = w_enrollment_init(local_target, local_cert, keys);
    *state = cfg;
    test_mode = 1;
    return 0;
}

//Teardown
int test_teardown_w_enrollment_request_key(void **state) {
    w_enrollment_ctx *cfg = *state;
    os_free(cfg->target_cfg->agent_name);
    os_free(cfg->target_cfg->centralized_group);
    os_free(cfg->target_cfg->manager_name);
    os_free(cfg->target_cfg->sender_ip);
    os_free(cfg->target_cfg);
    w_enrollment_cert_destroy(cfg->cert_cfg);
    os_free(cfg->keys);

    w_enrollment_destroy(cfg);
    test_mode = 0;
    return 0;
}

int test_setup_ssl_context(void **state) {
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    SSL *ssl = __real_SSL_new(ctx);
    SSL_CTX_free(ctx);
    *state = ssl;
    setup_file_ops(state);
    return 0;
}

//Teardown
int test_teardown_ssl_context(void **state) {
    SSL_free(*state);
    teardown_file_ops(state);
    return 0;
}

int test_setup_enrollment_load_pass(void **state) {
    w_enrollment_cert *cert_cfg = w_enrollment_cert_init();
    *state = cert_cfg;
    test_mode = 1;
    return 0;
}

int test_teardown_enrollment_load_pass(void **state) {
    w_enrollment_cert *cert_cfg;
    cert_cfg = *state;
    w_enrollment_cert_destroy(cert_cfg);

    test_mode = 0;
    return 0;
}

/**********************************************/
/************* w_enrollment_concat_src_ip ****************/
void test_w_enrollment_concat_src_ip_invalid_ip(void **state) {
    char *buf = *state;
    const char* sender_ip = "256.300.1";
    expect_string(__wrap_OS_IsValidIP, ip_address, sender_ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    expect_string(__wrap__merror, formatted_msg, "Invalid IP address provided for sender IP.");
    int ret = w_enrollment_concat_src_ip(buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buf), sender_ip, 0);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_concat_src_ip_valid_ip(void **state) {
    char *buf = *state;
    const char* sender_ip = "192.168.1.1";
    expect_string(__wrap_OS_IsValidIP, ip_address, sender_ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    int ret = w_enrollment_concat_src_ip(buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buf), sender_ip, 0);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, " IP:'192.168.1.1'");
}

void test_w_enrollment_concat_src_ip_empty_ip(void **state) {
    char *buf = *state;
    const char* sender_ip = NULL;

    int ret = w_enrollment_concat_src_ip(buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buf), sender_ip, 1);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, " IP:'src'");
}

void test_w_enrollment_concat_src_ip_incomaptible_opt(void **state) {
    char *buf = *state;
    const char* sender_ip ="192.168.1.1";

    expect_string(__wrap__merror, formatted_msg, "Incompatible sender_ip options: Forcing IP while using use_source_ip flag.");
    int ret = w_enrollment_concat_src_ip(buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buf), sender_ip, 1);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_concat_src_ip_small_buff(void **state) {
    int ret = 0;
    char *buf = *state;
    const char* sender_ip = "192.168.1.1";

    expect_string(__wrap_OS_IsValidIP, ip_address, sender_ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    ret = w_enrollment_concat_src_ip(buf, 30 - strlen(buf), sender_ip, 0);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, " IP:'192.168.1.1'");

    expect_string(__wrap_OS_IsValidIP, ip_address, sender_ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    ret = w_enrollment_concat_src_ip(buf, 30 - strlen(buf), sender_ip, 0);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, " IP:'192.168.1.1' IP:'192.168");
}

void test_w_enrollment_concat_src_ip_default(void **state) {
    char *buf = *state;
    const char* sender_ip = NULL;

    int ret = w_enrollment_concat_src_ip(buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buf), sender_ip, 0);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, "");
}

void test_w_enrollment_concat_src_ip_empty_buff(void **state) {
    expect_assert_failure(w_enrollment_concat_src_ip(NULL, 0, NULL, 0));
}

/**********************************************/
/************* w_enrollment_concat_group ****************/
void test_w_enrollment_concat_group_empty_buff(void **state) {
    expect_assert_failure(w_enrollment_concat_group(NULL, "EXAMPLE_GROUP"));
}

void test_w_enrollment_concat_group_empty_group(void **state) {
    char *buf = *state;
    expect_assert_failure(w_enrollment_concat_group(buf, NULL));
}

void test_w_enrollment_concat_group(void **state) {
    char *buf = *state;
    const char *group = "EXAMPLE_GROUP";
    w_enrollment_concat_group(buf, group);
    assert_string_equal(buf, " G:'EXAMPLE_GROUP'");
}

/**********************************************/
/************* w_enrollment_concat_key ****************/
void test_w_enrollment_concat_key_empty_buff(void **state) {
    keyentry key;

    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);

    expect_assert_failure(w_enrollment_concat_key(NULL, &key));

    free_keyentry(&key);
}

void test_w_enrollment_concat_key_empty_key_structure(void **state) {
    char *buf = *state;
    expect_assert_failure(w_enrollment_concat_key(buf, NULL));
}

void test_w_enrollment_concat_key(void **state) {
    char *buf = *state;
    keyentry key;

    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, RAW_KEY);

    w_enrollment_concat_key(buf, &key);

    assert_string_equal(buf, " K:'0965e68d9935a35530910bf32d35052995efe7bd'");

    free_keyentry(&key);
}

/**********************************************/
/********** w_enrollment_verify_ca_certificate *************/
void test_w_enrollment_verify_ca_certificate_null_connection(void **state) {
    expect_assert_failure(w_enrollment_verify_ca_certificate(NULL, "certificate_path", "hostname"));
}

void test_w_enrollment_verify_ca_certificate_no_certificate(void **state) {
    SSL *ssl = *state;
    expect_string(__wrap__mdebug1, formatted_msg, "Registering agent to unverified manager");
    int retval = w_enrollment_verify_ca_certificate(ssl, NULL, "hostname");
    assert_int_equal(retval, 0);
}

void test_verificy_ca_certificate_invalid_certificate(void **state) {
    SSL *ssl = *state;
    const char *hostname = "hostname";
    expect_value(__wrap_check_x509_cert, ssl, ssl);
    expect_string(__wrap_check_x509_cert, manager, hostname);
    will_return(__wrap_check_x509_cert, VERIFY_FALSE);

    expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");
    expect_string(__wrap__merror, formatted_msg, "Unable to verify server certificate");
    int retval = w_enrollment_verify_ca_certificate(ssl, "BAD_CERTIFICATE", "hostname");
    assert_int_equal(retval, 1);
}

void test_verificy_ca_certificate_valid_certificate(void **state) {
    SSL *ssl = *state;
    const char *hostname = "hostname";
    expect_value(__wrap_check_x509_cert, ssl, ssl);
    expect_string(__wrap_check_x509_cert, manager, hostname);
    will_return(__wrap_check_x509_cert, VERIFY_TRUE);

    expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");
    expect_string(__wrap__minfo, formatted_msg, "Manager has been verified successfully");
    int retval = w_enrollment_verify_ca_certificate(ssl, "GOOD_CERTIFICATE", "hostname");
    assert_int_equal(retval, 0);

}

/**********************************************/
/********** w_enrollment_connect *******/
void test_w_enrollment_connect_empty_address(void **state) {
    w_enrollment_ctx *cfg = *state;
    expect_assert_failure(w_enrollment_connect(cfg, NULL, 0));
}

void test_w_enrollment_connect_empty_config(void **state) {
    expect_assert_failure(w_enrollment_connect(NULL, "hostname", 0));
}

void test_w_enrollment_connect_invalid_hostname(void **state) {
    w_enrollment_ctx *cfg = *state;

    expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
    will_return(__wrap_OS_GetHost, NULL);
    expect_string(__wrap__merror, formatted_msg, "Could not resolve hostname: valid_hostname\n");

    int ret = w_enrollment_connect(cfg, cfg->target_cfg->manager_name, 0);
    assert_int_equal(ret, ENROLLMENT_WRONG_CONFIGURATION);
}

void test_w_enrollment_connect_could_not_setup(void **state) {
    w_enrollment_ctx *cfg = *state;

    expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, NULL);

    expect_string(__wrap__merror, formatted_msg, "Could not set up SSL connection! Check certification configuration.");
    int ret = w_enrollment_connect(cfg, cfg->target_cfg->manager_name, 0);
    assert_int_equal(ret, ENROLLMENT_WRONG_CONFIGURATION);
}

void test_w_enrollment_connect_socket_error(void **state) {
    w_enrollment_ctx *cfg = *state;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);

    // GetHost
    expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, -1);

    expect_string(__wrap__merror, formatted_msg, "(1208): Unable to connect to enrollment service at '[127.0.0.1]:1234'");
    int ret = w_enrollment_connect(cfg, cfg->target_cfg->manager_name, 0);
    assert_int_equal(ret, ENROLLMENT_CONNECTION_FAILURE);
}

void test_w_enrollment_connect_set_timeout_error(void **state) {
    w_enrollment_ctx *cfg = *state;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    // GetHost
    expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, 5);
    // OS_SetRecvTimeout
    will_return(__wrap_OS_SetRecvTimeout, -1);
    expect_string(__wrap__mwarn, formatted_msg, "(1339) Cannot set timeout: No such file or directory (2).");

    // Connect SSL
    expect_value(__wrap_SSL_new, ctx, ctx);
    cfg->ssl = __real_SSL_new(ctx);
    will_return(__wrap_SSL_new, cfg->ssl);
    will_return(__wrap_SSL_connect, -1);

    expect_value(__wrap_SSL_get_error, i, -1);
    will_return(__wrap_SSL_get_error, 100);
    expect_string(__wrap__merror, formatted_msg, "SSL error (100). Connection refused by the manager. Maybe the port specified is incorrect.");

    // Close socket
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);

    int ret = w_enrollment_connect(cfg, cfg->target_cfg->manager_name, 0);
    assert_int_equal(ret, ENROLLMENT_CONNECTION_FAILURE);
}

void test_w_enrollment_connect_SSL_connect_error(void **state) {
    w_enrollment_ctx *cfg = *state;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    // GetHost
    expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, 5);
    // OS_SetRecvTimeout
    will_return(__wrap_OS_SetRecvTimeout, 0);
    // Connect SSL
    expect_value(__wrap_SSL_new, ctx, ctx);
    cfg->ssl = __real_SSL_new(ctx);
    will_return(__wrap_SSL_new, cfg->ssl);
    will_return(__wrap_SSL_connect, -1);

    expect_value(__wrap_SSL_get_error, i, -1);
    will_return(__wrap_SSL_get_error, 100);
    expect_string(__wrap__merror, formatted_msg, "SSL error (100). Connection refused by the manager. Maybe the port specified is incorrect.");

    // Close socket
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);

    int ret = w_enrollment_connect(cfg, cfg->target_cfg->manager_name, 0);
    assert_int_equal(ret, ENROLLMENT_CONNECTION_FAILURE);
}

void test_w_enrollment_connect_success(void **state) {
    w_enrollment_ctx *cfg = *state;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    // GetHost
    expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, 5);
    // OS_SetRecvTimeout
    will_return(__wrap_OS_SetRecvTimeout, 0);
    // Connect SSL
    expect_value(__wrap_SSL_new, ctx, ctx);
    cfg->ssl = __real_SSL_new(ctx);
    will_return(__wrap_SSL_new, cfg->ssl);
    will_return(__wrap_SSL_connect, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "(1209): Connected to enrollment service at '[127.0.0.1]:1234'");

    // verify_ca_certificate
    expect_value(__wrap_check_x509_cert, ssl, cfg->ssl);
    expect_string(__wrap_check_x509_cert, manager, cfg->target_cfg->manager_name);
    will_return(__wrap_check_x509_cert, VERIFY_TRUE);
    expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");
    expect_string(__wrap__minfo, formatted_msg, "Manager has been verified successfully");

    int ret = w_enrollment_connect(cfg, cfg->target_cfg->manager_name, 0);
    assert_int_equal(ret, 5);
}

/**********************************************/
/********** w_enrollment_send_message *******/
void test_w_enrollment_send_message_empty_config(void **state) {
    expect_assert_failure(w_enrollment_send_message(NULL));
}

void test_w_enrollment_send_message_wrong_hostname(void **state) {
    w_enrollment_ctx *cfg = *state;
#ifdef WIN32
    will_return(wrap_gethostname, NULL);
    will_return(wrap_gethostname, -1);
#else
    will_return(__wrap_gethostname, NULL);
    will_return(__wrap_gethostname, -1);
#endif
    expect_string(__wrap__merror, formatted_msg, "Unable to extract hostname. Custom agent name not set.");
    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_send_message_invalid_hostname(void **state) {
    w_enrollment_ctx *cfg = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid agent name \"Invalid\'!@Hostname\'\". Please pick a valid name.");
    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_send_message_fix_invalid_hostname(void **state) {
    w_enrollment_ctx *cfg = *state;
#ifdef WIN32
    will_return(wrap_gethostname, "Invalid\'!@Hostname\'");
    will_return(wrap_gethostname, 0);
#else
    will_return(__wrap_gethostname, "Invalid\'!@Hostname\'");
    will_return(__wrap_gethostname, 0);
#endif
    // If gethostname returns an invalid string should be fixed by OS_ConvertToValidAgentName
    expect_string(__wrap__minfo, formatted_msg, "Using agent name as: InvalidHostname");
    expect_value(__wrap_SSL_write, ssl, cfg->ssl);
    char buff[128];
    snprintf(buff,128,"OSSEC A:'InvalidHostname' V:'v4.5.0'\n");

    expect_string(__wrap_SSL_write, buf, buff);
    will_return(__wrap_SSL_write, -1);
    expect_string(__wrap__merror, formatted_msg, "SSL write error (unable to send message.)");
    expect_string(__wrap__merror, formatted_msg, "If Agent verification is enabled, agent key and certificates are required!");
    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_send_message_concat_src_ip_error(void **state) {
    w_enrollment_ctx *cfg = *state;
#ifdef WIN32
    will_return(wrap_gethostname, "host.name");
    will_return(wrap_gethostname, 0);
#else
    will_return(__wrap_gethostname, "host.name");
    will_return(__wrap_gethostname, 0);
#endif
    expect_string(__wrap__minfo, formatted_msg, "Using agent name as: host.name");

    // Force an incompatible sender_ip and use_src_ip combination
    cfg->target_cfg->sender_ip = strdup("192.168.1.1");
    cfg->target_cfg->use_src_ip = 1;
    expect_string(__wrap__merror, formatted_msg, "Incompatible sender_ip options: Forcing IP while using use_source_ip flag.");

    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_send_message_ssl_error(void **state) {
    w_enrollment_ctx *cfg = *state;
#ifdef WIN32
    will_return(wrap_gethostname, "host.name");
    will_return(wrap_gethostname, 0);
#else
    will_return(__wrap_gethostname, "host.name");
    will_return(__wrap_gethostname, 0);
#endif
    expect_string(__wrap__minfo, formatted_msg, "Using agent name as: host.name");
    expect_value(__wrap_SSL_write, ssl, cfg->ssl);

    char buff[128];
    snprintf(buff,128,"OSSEC A:'host.name' V:'v4.5.0'\n");

    expect_string(__wrap_SSL_write, buf, buff);
    will_return(__wrap_SSL_write, -1);
    expect_string(__wrap__merror, formatted_msg, "SSL write error (unable to send message.)");
    expect_string(__wrap__merror, formatted_msg, "If Agent verification is enabled, agent key and certificates are required!");
    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_send_message_success(void **state) {
    w_enrollment_ctx *cfg = *state;
    // Configuring a key to be concatenated
    cfg->keys->keyentries = (keyentry **)realloc(cfg->keys->keyentries,
                                            (cfg->keys->keysize + 2) * sizeof(keyentry *));
    cfg->keys->keyentries[cfg->keys->keysize + 1] = NULL;
    os_calloc(1, sizeof(keyentry), cfg->keys->keyentries[cfg->keys->keysize]);
    keyentry_init(cfg->keys->keyentries[cfg->keys->keysize], NEW_AGENT1, AGENT1_ID, NEW_IP1, RAW_KEY);
    cfg->keys->keysize = 1;
    expect_string(__wrap__minfo, formatted_msg, "Using agent name as: test_agent");
    expect_string(__wrap_OS_IsValidIP, ip_address, "192.168.1.1");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
    expect_value(__wrap_SSL_write, ssl, cfg->ssl);

    char buff[256];
    snprintf(buff,256,"OSSEC PASS: test_password OSSEC A:'test_agent' V:'v4.5.0' G:'test_group' IP:'192.168.1.1' K:'0965e68d9935a35530910bf32d35052995efe7bd'\n");

    expect_string(__wrap_SSL_write, buf, buff);
    will_return(__wrap_SSL_write, 0);
    expect_string(__wrap__mdebug1, formatted_msg,"Request sent to manager");
    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, 0);
    // Free the configured key memory
    for (unsigned int i = 0; i <= cfg->keys->keysize; i++) {
        if (cfg->keys->keyentries[i]) {
            OS_FreeKey(cfg->keys->keyentries[i]);
            cfg->keys->keyentries[i] = NULL;
        }
    }
    os_free(cfg->keys->keyentries);
}

void test_w_enrollment_send_message_success_different_hostname(void **state) {
    w_enrollment_ctx *cfg = *state;
    // Configuring a key to be concatenated
    cfg->keys->keyentries = (keyentry **)realloc(cfg->keys->keyentries,
                                            (cfg->keys->keysize + 2) * sizeof(keyentry *));
    cfg->keys->keyentries[cfg->keys->keysize + 1] = NULL;
    os_calloc(1, sizeof(keyentry), cfg->keys->keyentries[cfg->keys->keysize]);
    keyentry_init(cfg->keys->keyentries[cfg->keys->keysize], NEW_AGENT1, AGENT1_ID, NEW_IP1, RAW_KEY);
    cfg->keys->keysize = 1;
    // Configuring hostname
#ifdef WIN32
    will_return(wrap_gethostname, "host.name");
    will_return(wrap_gethostname, 0);
#else
    will_return(__wrap_gethostname, "host.name");
    will_return(__wrap_gethostname, 0);
#endif
    expect_string(__wrap__minfo, formatted_msg, "Using agent name as: host.name");
    expect_value(__wrap_SSL_write, ssl, cfg->ssl);

    char buff[128];
    snprintf(buff,128,"OSSEC A:'host.name' V:'v4.5.0' K:'0965e68d9935a35530910bf32d35052995efe7bd'\n");

    expect_string(__wrap_SSL_write, buf, buff);
    will_return(__wrap_SSL_write, 0);
    expect_string(__wrap__mdebug1, formatted_msg,"Request sent to manager");
    int ret = w_enrollment_send_message(cfg);
    assert_int_equal(ret, 0);
    // Free the configured key memory
    for (unsigned int i = 0; i <= cfg->keys->keysize; i++) {
        if (cfg->keys->keyentries[i]) {
            OS_FreeKey(cfg->keys->keyentries[i]);
            cfg->keys->keyentries[i] = NULL;
        }
    }
    os_free(cfg->keys->keyentries);
}

/**********************************************/
/********** w_enrollment_send_message *******/
void test_w_enrollment_store_key_entry_null_key(void **state) {
    expect_assert_failure(w_enrollment_store_key_entry(NULL));
}

void test_w_enrollment_store_key_entry_cannot_open(void **state) {
    const char* key_string = "KEY EXAMPLE STRING";
    char key_file[1024];
#ifdef WIN32
    expect_string(__wrap_wfopen, path, KEYS_FILE);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 0);
#else
    expect_string(__wrap_TempFile, source, KEYS_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, NULL);
    will_return(__wrap_TempFile, NULL);
    will_return(__wrap_TempFile, -1);
#endif
    snprintf(key_file, 1024, "(1103): Could not open file '%s' due to [(2)-(No such file or directory)].", KEYS_FILE);
    expect_string(__wrap__merror, formatted_msg, key_file);
    int ret = w_enrollment_store_key_entry(key_string);
    assert_int_equal(ret, -1);
}

#ifndef WIN32
void test_w_enrollment_store_key_entry_chmod_fail(void **state) {
    FILE file;
    const char* key_string = "KEY EXAMPLE STRING";
    char key_file[1024];

    expect_string(__wrap_TempFile, source, KEYS_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup("client.keys.temp"));
    will_return(__wrap_TempFile, 6);
    will_return(__wrap_TempFile, 0);

    expect_value(__wrap_fclose, _File, 6);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap_chmod, path, "client.keys.temp");
    will_return(__wrap_chmod, -1);

    snprintf(key_file, 1024, "(1127): Could not chmod object '%s' due to [(2)-(No such file or directory)].", "client.keys.temp");
    expect_string(__wrap__merror, formatted_msg, key_file);

    int ret = w_enrollment_store_key_entry(key_string);
    assert_int_equal(ret, -1);
}
#endif

void test_w_enrollment_store_key_entry_success(void **state) {
    FILE file;
    const char* key_string = "KEY EXAMPLE STRING";
#ifdef WIN32
    expect_string(__wrap_wfopen, path, KEYS_FILE);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, &file);

    expect_value(__wrap_fclose, _File, &file);
    will_return(__wrap_fclose, 1);

    expect_value(wrap_fprintf, __stream, &file);
    expect_string(wrap_fprintf, formatted_msg, "KEY EXAMPLE STRING\n");
    will_return(wrap_fprintf, 0);
#else
    expect_string(__wrap_TempFile, source, KEYS_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup("client.keys.temp"));
    will_return(__wrap_TempFile, 6);
    will_return(__wrap_TempFile, 0);

    expect_string(__wrap_chmod, path, "client.keys.temp");
    will_return(__wrap_chmod, 0);

    expect_value(__wrap_fclose, _File, 6);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_fprintf, __stream, 6);
    expect_string(__wrap_fprintf, formatted_msg, "KEY EXAMPLE STRING\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_OS_MoveFile, src, "client.keys.temp");
    expect_string(__wrap_OS_MoveFile, dst, KEYS_FILE);
    will_return(__wrap_OS_MoveFile, 0);
#endif
    int ret = w_enrollment_store_key_entry(key_string);
    assert_int_equal(ret, 0);
}

/**********************************************/
/********** w_enrollment_send_message *******/
void test_w_enrollment_process_agent_key_empty_buff(void **state) {
    expect_assert_failure(w_enrollment_process_agent_key(NULL));
}

void test_w_enrollment_process_agent_key_short_buff(void **state) {
    expect_assert_failure(w_enrollment_process_agent_key("short"));
}

void test_w_enrollment_process_agent_key_invalid_format(void **state) {
    char key[] = "OSSEC KEY WRONG FORMAT";
    expect_string(__wrap__merror, formatted_msg, "Invalid keys format received.");
    w_enrollment_process_agent_key(key);
}

void test_w_enrollment_process_agent_key_invalid_key(void **state) {
    char key[] = "OSSEC K:'006 ubuntu1610 NOT_AN_IP 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f'";
    expect_string(__wrap_OS_IsValidIP, ip_address, "NOT_AN_IP");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);
    expect_string(__wrap__merror, formatted_msg, "One of the received key parameters does not have a valid format");
    int ret = w_enrollment_process_agent_key(key);
    assert_int_equal(ret,-1);
}

void test_w_enrollment_process_agent_key_valid_key(void **state) {
    char key[] = "OSSEC K:'006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f'";
    expect_string(__wrap_OS_IsValidIP, ip_address, "192.168.1.1");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
#ifdef WIN32
    expect_string(__wrap_wfopen, path, KEYS_FILE);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 4);

    expect_value(__wrap_fclose, _File, 4);
    will_return(__wrap_fclose, 1);

    expect_value(wrap_fprintf, __stream, 4);
    expect_string(wrap_fprintf, formatted_msg, "006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f\n");
    will_return(wrap_fprintf, 0);
#else
    expect_string(__wrap_TempFile, source, KEYS_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup("client.keys.temp"));
    will_return(__wrap_TempFile, 4);
    will_return(__wrap_TempFile, 0);

    expect_string(__wrap_chmod, path, "client.keys.temp");
    will_return(__wrap_chmod, 0);

    expect_value(__wrap_fclose, _File, 4);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_fprintf, __stream, 4);
    expect_string(__wrap_fprintf, formatted_msg, "006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_OS_MoveFile, src, "client.keys.temp");
    expect_string(__wrap_OS_MoveFile, dst, KEYS_FILE);
    will_return(__wrap_OS_MoveFile, 0);
#endif
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    int ret = w_enrollment_process_agent_key(key);
    assert_int_equal(ret,0);
}

/**********************************************/
/******* w_enrollment_process_response ********/
void test_w_enrollment_process_response_ssl_null(void **state) {
    expect_assert_failure(w_enrollment_process_response(NULL));
}

void test_w_enrollment_process_response_ssl_error(void **state) {
     SSL *ssl = *state;
    expect_string(__wrap__minfo, formatted_msg, "Waiting for server reply");
    expect_value(__wrap_SSL_read, ssl, ssl);
    expect_any(__wrap_SSL_read, buf);
    expect_any(__wrap_SSL_read, num);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, -1);

    expect_value(__wrap_SSL_get_error, i, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);

    expect_string(__wrap__merror, formatted_msg, "SSL read (unable to receive message)");
    expect_string(__wrap__merror, formatted_msg, "If Agent verification is enabled, agent key and certificates may be incorrect!");

    int ret = w_enrollment_process_response(ssl);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_process_response_message_error(void **state) {
    SSL *ssl = *state;
    expect_string(__wrap__minfo, formatted_msg, "Waiting for server reply");

    expect_value(__wrap_SSL_read, ssl, ssl);
    expect_any(__wrap_SSL_read, buf);
    expect_any(__wrap_SSL_read, num);

    will_return(__wrap_SSL_read, "ERROR: Unable to add agent.");
    will_return(__wrap_SSL_read, strlen("ERROR: Unable to add agent."));

    expect_string(__wrap__merror, formatted_msg, "Unable to add agent. (from manager)");

    expect_value(__wrap_SSL_read, ssl, ssl);
    expect_any(__wrap_SSL_read, buf);
    expect_any(__wrap_SSL_read, num);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, 0);

    expect_value(__wrap_SSL_get_error, i, 0);
    will_return(__wrap_SSL_get_error, SSL_ERROR_NONE);

    expect_string(__wrap__mdebug1, formatted_msg, "Connection closed.");

    int ret = w_enrollment_process_response(ssl);
    assert_int_equal(ret, -1);
}

void test_w_enrollment_process_response_success(void **state) {
    const char *string = "OSSEC K:'006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f'";
    SSL *ssl = *state;
    expect_string(__wrap__minfo, formatted_msg, "Waiting for server reply");
    expect_value(__wrap_SSL_read, ssl, ssl);
    expect_any(__wrap_SSL_read, buf);
    expect_any(__wrap_SSL_read, num);
    will_return(__wrap_SSL_read, string);
    will_return(__wrap_SSL_read, strlen(string));

    // w_enrollment_process_agent_key
    {
        expect_string(__wrap_OS_IsValidIP, ip_address, "192.168.1.1");
        expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
        will_return(__wrap_OS_IsValidIP, 1);
#ifdef WIN32
        expect_string(__wrap_wfopen, path, KEYS_FILE);
        expect_string(__wrap_wfopen, mode, "w");
        will_return(__wrap_wfopen, 4);

        expect_value(__wrap_fclose, _File, 4);
        will_return(__wrap_fclose, 1);

        expect_value(wrap_fprintf, __stream, 4);
        expect_string(wrap_fprintf, formatted_msg, "006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f\n");
        will_return(wrap_fprintf, 0);
#else
        expect_string(__wrap_TempFile, source, KEYS_FILE);
        expect_value(__wrap_TempFile, copy, 0);
        will_return(__wrap_TempFile, strdup("client.keys.temp"));
        will_return(__wrap_TempFile, 4);
        will_return(__wrap_TempFile, 0);

        expect_string(__wrap_chmod, path, "client.keys.temp");
        will_return(__wrap_chmod, 0);

        expect_value(__wrap_fclose, _File, 4);
        will_return(__wrap_fclose, 1);

        expect_value(__wrap_fprintf, __stream, 4);
        expect_string(__wrap_fprintf, formatted_msg, "006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f\n");
        will_return(__wrap_fprintf, 0);

        expect_string(__wrap_OS_MoveFile, src, "client.keys.temp");
        expect_string(__wrap_OS_MoveFile, dst, KEYS_FILE);
        will_return(__wrap_OS_MoveFile, 0);
#endif
        expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    }
    expect_value(__wrap_SSL_get_error, i, strlen(string));
    will_return(__wrap_SSL_get_error, SSL_ERROR_NONE);
    expect_string(__wrap__mdebug1, formatted_msg, "Connection closed.");

    int ret = w_enrollment_process_response(ssl);
    assert_int_equal(ret, 0);
}

/**********************************************/
/******* w_enrollment_request_key ********/
void test_w_enrollment_request_key_null_cfg(void **state) {
    expect_assert_failure(w_enrollment_request_key(NULL, "server_adress", 0));
}

void test_w_enrollment_request_key(void **state) {
    w_enrollment_ctx *cfg = *state;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    char buff[128];

    expect_string(__wrap__minfo, formatted_msg, "Requesting a key from server: valid_hostname");

    // Close socket
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);

    // w_enrollment_connect
    {
        // GetHost
        expect_string(__wrap_OS_GetHost, host, cfg->target_cfg->manager_name);
        will_return(__wrap_OS_GetHost, strdup("192.168.1.1"));
        // os_ssl_keys
        expect_value(__wrap_os_ssl_keys, is_server, 0);
        expect_value(__wrap_os_ssl_keys, os_dir, NULL);
        expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
        expect_string(__wrap_os_ssl_keys, cert, "CERT");
        expect_string(__wrap_os_ssl_keys, key, "KEY");
        expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
        expect_value(__wrap_os_ssl_keys, auto_method, 0);
        will_return(__wrap_os_ssl_keys, ctx);
        // OS_ConnectTCP
        expect_value(__wrap_OS_ConnectTCP, _port, 1234);
        expect_string(__wrap_OS_ConnectTCP, _ip, "192.168.1.1");
        expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
        will_return(__wrap_OS_ConnectTCP, 5);
        // OS_SetRecvTimeout
        will_return(__wrap_OS_SetRecvTimeout, 0);
        // Connect SSL
        expect_value(__wrap_SSL_new, ctx, ctx);
        cfg->ssl = __real_SSL_new(ctx);
        will_return(__wrap_SSL_new, cfg->ssl);
        will_return(__wrap_SSL_connect, 1);

        expect_string(__wrap__mdebug1, formatted_msg, "(1209): Connected to enrollment service at '[192.168.1.1]:1234'");

        // verify_ca_certificate
        expect_value(__wrap_check_x509_cert, ssl, cfg->ssl);
        expect_string(__wrap_check_x509_cert, manager, cfg->target_cfg->manager_name);
        will_return(__wrap_check_x509_cert, VERIFY_TRUE);
        expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");
        expect_string(__wrap__minfo, formatted_msg, "Manager has been verified successfully");
    }
    // w_enrollment_send_message
    {
        expect_string(__wrap__minfo, formatted_msg, "Using agent name as: test_agent");
        expect_string(__wrap_OS_IsValidIP, ip_address, "192.168.1.1");
        expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
        will_return(__wrap_OS_IsValidIP, 1);
        expect_value(__wrap_SSL_write, ssl, cfg->ssl);

        snprintf(buff,128,"OSSEC PASS: test_password OSSEC A:'test_agent' V:'v4.5.0' G:'test_group' IP:'192.168.1.1'\n");
        expect_string(__wrap_SSL_write, buf, buff);
        will_return(__wrap_SSL_write, 0);
        expect_string(__wrap__mdebug1, formatted_msg,"Request sent to manager");
    }
    // w_enrollment_process_response
    {
        const char *string = "OSSEC K:'006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f'";
        expect_string(__wrap__minfo, formatted_msg, "Waiting for server reply");
        expect_value(__wrap_SSL_read, ssl, cfg->ssl);
        expect_any(__wrap_SSL_read, buf);
        expect_any(__wrap_SSL_read, num);
        will_return(__wrap_SSL_read, string);
        will_return(__wrap_SSL_read, strlen(string));

        // w_enrollment_process_agent_key
        {
            expect_string(__wrap_OS_IsValidIP, ip_address, "192.168.1.1");
            expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
            will_return(__wrap_OS_IsValidIP, 1);
#ifdef WIN32
            expect_string(__wrap_wfopen, path, KEYS_FILE);
            expect_string(__wrap_wfopen, mode, "w");
            will_return(__wrap_wfopen, 4);

            expect_value(__wrap_fclose, _File, 4);
            will_return(__wrap_fclose, 1);

            expect_value(wrap_fprintf, __stream, 4);
            expect_string(wrap_fprintf, formatted_msg, "006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f\n");
            will_return(wrap_fprintf, 0);
#else
            expect_string(__wrap_TempFile, source, KEYS_FILE);
            expect_value(__wrap_TempFile, copy, 0);
            will_return(__wrap_TempFile, strdup("client.keys.temp"));
            will_return(__wrap_TempFile, 4);
            will_return(__wrap_TempFile, 0);

            expect_string(__wrap_chmod, path, "client.keys.temp");
            will_return(__wrap_chmod, 0);

            expect_value(__wrap_fclose, _File, 4);
            will_return(__wrap_fclose, 1);

            expect_value(__wrap_fprintf, __stream, 4);
            expect_string(__wrap_fprintf, formatted_msg, "006 ubuntu1610 192.168.1.1 95fefb8f0fe86bb8121f3f5621f2916c15a998728b3d50479aa64e6430b5a9f\n");
            will_return(__wrap_fprintf, 0);

            expect_string(__wrap_OS_MoveFile, src, "client.keys.temp");
            expect_string(__wrap_OS_MoveFile, dst, KEYS_FILE);
            will_return(__wrap_OS_MoveFile, 0);
#endif
            expect_string(__wrap__minfo, formatted_msg, "Valid key received");
        }
        expect_value(__wrap_SSL_get_error, i, strlen(string));
        will_return(__wrap_SSL_get_error, SSL_ERROR_NONE);
        expect_string(__wrap__mdebug1, formatted_msg, "Connection closed.");
    }
    int ret = w_enrollment_request_key(cfg, NULL, 0);
    assert_int_equal(ret, 0);
}

/**********************************************/
/******* w_enrollment_extract_agent_name ********/
void test_w_enrollment_extract_agent_name_localhost_allowed(void **state) {
    w_enrollment_ctx *cfg = *state;
    cfg->allow_localhost = true; // Allow localhost
#ifdef WIN32
    will_return(wrap_gethostname, "localhost");
    will_return(wrap_gethostname, 0);
#else
    will_return(__wrap_gethostname, "localhost");
    will_return(__wrap_gethostname, 0);
#endif
    char *lhostname = w_enrollment_extract_agent_name(cfg);
    assert_string_equal( lhostname, "localhost");
    os_free(lhostname);
}

void test_w_enrollment_extract_agent_name_localhost_not_allowed(void **state) {
    w_enrollment_ctx *cfg = *state;
    cfg->allow_localhost = false; // Do not allow localhost
#ifdef WIN32
    will_return(wrap_gethostname, "localhost");
    will_return(wrap_gethostname, 0);
#else
    will_return(__wrap_gethostname, "localhost");
    will_return(__wrap_gethostname, 0);
#endif
    expect_string(__wrap__merror, formatted_msg, "(4104): Invalid hostname: 'localhost'.");

    char *lhostname = w_enrollment_extract_agent_name(cfg);
    assert_int_equal( lhostname, NULL);
}

/******* w_enrollment_load_pass ********/
void test_w_enrollment_load_pass_null_cert(void **state) {
    expect_assert_failure(w_enrollment_load_pass(NULL));
}

void test_w_enrollment_load_pass_empty_file(void **state) {
    w_enrollment_cert *cert = *state;

    expect_string(__wrap_wfopen, path, AUTHD_PASS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 4);
#ifdef WIN32
    expect_value(__wrap_fclose, _File, 4);
    will_return(__wrap_fclose, 1);

    expect_value(wrap_fgets, __stream, 4);
    will_return(wrap_fgets, "");
#else
    expect_value(__wrap_fclose, _File, 4);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_fgets, __stream, 4);
    will_return(__wrap_fgets, NULL);
#endif
    char buff[1024];
    snprintf(buff, 1024, "Using password specified on file: %s", AUTHD_PASS);
    expect_string(__wrap__minfo, formatted_msg, buff);
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");

    w_enrollment_load_pass(cert);
    assert_int_equal(cert->authpass, NULL);
}

void test_w_enrollment_load_pass_file_with_content(void **state) {
    w_enrollment_cert *cert = *state;

    expect_string(__wrap_wfopen, path, AUTHD_PASS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 4);
#ifdef WIN32
    expect_value(__wrap_fclose, _File, 4);
    will_return(__wrap_fclose, 1);

    expect_value(wrap_fgets, __stream, 4);
    will_return(wrap_fgets, "content_password");
#else
    expect_value(__wrap_fclose, _File, 4);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_fgets, __stream, 4);
    will_return(__wrap_fgets, "content_password");
#endif
    char buff[1024];
    snprintf(buff, 1024, "Using password specified on file: %s", AUTHD_PASS);
    expect_string(__wrap__minfo, formatted_msg, buff);

    w_enrollment_load_pass(cert);
    assert_string_equal(cert->authpass, "content_password");
}

/**********************************************/
int main() {
    const struct CMUnitTest tests[] = {
        // w_enrollment_concat_src_ip
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_src_ip_invalid_ip, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_src_ip_valid_ip, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_src_ip_empty_ip, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_src_ip_incomaptible_opt, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_src_ip_small_buff, test_setup_concats_small_buff, test_teardown_concats),
        cmocka_unit_test(test_w_enrollment_concat_src_ip_empty_buff),
        // w_enrollment_concat_group
        cmocka_unit_test(test_w_enrollment_concat_group_empty_buff),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_group_empty_group, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_group, test_setup_concats, test_teardown_concats),
        // w_enrollment_concat_key
        cmocka_unit_test(test_w_enrollment_concat_key_empty_buff),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_key_empty_key_structure, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_w_enrollment_concat_key, test_setup_concats, test_teardown_concats),
        //  w_enrollment_verify_ca_certificate
        cmocka_unit_test_setup_teardown(test_w_enrollment_verify_ca_certificate_null_connection, test_setup_ssl_context, test_teardown_ssl_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_verify_ca_certificate_no_certificate, test_setup_ssl_context, test_teardown_ssl_context),
        cmocka_unit_test_setup_teardown(test_verificy_ca_certificate_invalid_certificate, test_setup_ssl_context, test_teardown_ssl_context),
        cmocka_unit_test_setup_teardown(test_verificy_ca_certificate_valid_certificate, test_setup_ssl_context, test_teardown_ssl_context),
        // w_enrollment_connect
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_empty_address, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_empty_config, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_invalid_hostname, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_could_not_setup, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_socket_error, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_set_timeout_error, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_SSL_connect_error, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_connect_success, test_setup_context, test_teardown_context),
        // w_enrollment_send_message
        cmocka_unit_test(test_w_enrollment_send_message_empty_config),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_wrong_hostname, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_invalid_hostname, test_setup_context_3, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_fix_invalid_hostname, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_concat_src_ip_error, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_ssl_error, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_success, test_setup_context_2, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_send_message_success_different_hostname, test_setup_context, test_teardown_context),
        // w_enrollment_store_key_entry
        cmocka_unit_test_setup_teardown(test_w_enrollment_store_key_entry_null_key, setup_file_ops, teardown_file_ops),
        cmocka_unit_test_setup_teardown(test_w_enrollment_store_key_entry_cannot_open, setup_file_ops, teardown_file_ops),
#ifndef WIN32
        cmocka_unit_test_setup_teardown(test_w_enrollment_store_key_entry_chmod_fail, setup_file_ops, teardown_file_ops),
#endif
        cmocka_unit_test_setup_teardown(test_w_enrollment_store_key_entry_success, setup_file_ops, teardown_file_ops),
        // w_enrollment_process_agent_key
        cmocka_unit_test(test_w_enrollment_process_agent_key_empty_buff),
        cmocka_unit_test(test_w_enrollment_process_agent_key_short_buff),
        cmocka_unit_test(test_w_enrollment_process_agent_key_invalid_format),
        cmocka_unit_test(test_w_enrollment_process_agent_key_invalid_key),
        cmocka_unit_test_setup_teardown(test_w_enrollment_process_agent_key_valid_key, setup_file_ops, teardown_file_ops),
        // w_enrollment_process_response
        cmocka_unit_test(test_w_enrollment_process_response_ssl_null),
        cmocka_unit_test_setup_teardown(test_w_enrollment_process_response_ssl_error, test_setup_ssl_context, test_teardown_ssl_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_process_response_message_error, test_setup_ssl_context, test_teardown_ssl_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_process_response_success, test_setup_ssl_context, test_teardown_ssl_context),
        // w_enrollment_request_key (wrapper)
        cmocka_unit_test(test_w_enrollment_request_key_null_cfg),
        cmocka_unit_test_setup_teardown(test_w_enrollment_request_key, test_setup_w_enrollment_request_key, test_teardown_w_enrollment_request_key),
        // w_enrollment_extract_agent_name
        cmocka_unit_test_setup_teardown(test_w_enrollment_extract_agent_name_localhost_allowed, test_setup_context, test_teardown_context),
        cmocka_unit_test_setup_teardown(test_w_enrollment_extract_agent_name_localhost_not_allowed, test_setup_context, test_teardown_context),
        // w_enrollment_load_pass
        cmocka_unit_test(test_w_enrollment_load_pass_null_cert),
        cmocka_unit_test_setup_teardown(test_w_enrollment_load_pass_empty_file, test_setup_enrollment_load_pass, test_teardown_enrollment_load_pass),
        cmocka_unit_test_setup_teardown(test_w_enrollment_load_pass_file_with_content, test_setup_enrollment_load_pass, test_teardown_enrollment_load_pass),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

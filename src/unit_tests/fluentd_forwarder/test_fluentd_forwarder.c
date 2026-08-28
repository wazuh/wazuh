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

#include <pthread.h>
#include <signal.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

typedef struct test_struct {
    wm_fluent_t *fluent;
    cJSON * configuration_dump;
} test_struct_t;

#define SOCKET_PATH "/tmp/socket-tmp"
#define TEST_CA_PATH "/tmp/wm_fluent_test_ca.pem"

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


// TLS test helpers

typedef struct test_tls_server_t {
    int sock;
    X509 * cert;
    EVP_PKEY * key;
} test_tls_server_t;

static EVP_PKEY * test_tls_gen_key() {
    return EVP_EC_gen("P-256");
}

/* Generate a certificate. If ca_cert is NULL, a self-signed CA certificate is
   generated, otherwise a leaf certificate holding the given subjectAltName */
static X509 * test_tls_gen_cert(EVP_PKEY * key, const char * cn, const char * san, X509 * ca_cert, EVP_PKEY * ca_key) {
    X509 * cert = X509_new();
    X509V3_CTX ctx;
    X509_EXTENSION * ext;

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert ? ca_cert : cert));

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert ? ca_cert : cert, cert, NULL, NULL, 0);

    ext = san ? X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san)
              : X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    X509_sign(cert, ca_key ? ca_key : key, EVP_sha256());
    return cert;
}

static void * test_tls_server_run(void * arg) {
    test_tls_server_t * server = (test_tls_server_t *)arg;
    SSL_CTX * ctx = SSL_CTX_new(TLS_method());
    SSL * ssl;
    BIO * bio;

    SSL_CTX_use_certificate(ctx, server->cert);
    SSL_CTX_use_PrivateKey(ctx, server->key);

    ssl = SSL_new(ctx);
    bio = BIO_new_socket(server->sock, 0);
    SSL_set_bio(ssl, bio, bio);
    SSL_accept(ssl);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return NULL;
}

/* Run a TLS handshake against a local server whose certificate holds the given
   subjectAltName, and is signed by the CA that the module is configured to trust */
static int test_tls_connect(wm_fluent_t * fluent, const char * address, const char * san) {
    EVP_PKEY * ca_key = test_tls_gen_key();
    X509 * ca_cert = test_tls_gen_cert(ca_key, "Wazuh Test CA", NULL, NULL, NULL);
    EVP_PKEY * server_key = test_tls_gen_key();
    X509 * server_cert = test_tls_gen_cert(server_key, "fluentd", san, ca_cert, ca_key);
    struct timeval timeout = { .tv_sec = 10 };
    test_tls_server_t server;
    pthread_t thread;
    int sockets[2];
    int retval;
    FILE * fp;

    signal(SIGPIPE, SIG_IGN);

    fp = fopen(TEST_CA_PATH, "w");
    assert_non_null(fp);
    PEM_write_X509(fp, ca_cert);
    fclose(fp);

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    server.sock = sockets[1];
    server.cert = server_cert;
    server.key = server_key;
    assert_int_equal(pthread_create(&thread, NULL, test_tls_server_run, &server), 0);

    fluent->address = (char *)address;
    fluent->certificate = TEST_CA_PATH;
    fluent->client_sock = sockets[0];

    retval = wm_fluent_ssl_connect(fluent);

    pthread_join(thread, NULL);

    SSL_free(fluent->ssl);
    fluent->ssl = NULL;
    SSL_CTX_free(fluent->ctx);
    fluent->ctx = NULL;
    fluent->address = NULL;
    fluent->certificate = NULL;
    fluent->client_sock = -1;

    close(sockets[0]);
    close(sockets[1]);
    X509_free(server_cert);
    EVP_PKEY_free(server_key);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    unlink(TEST_CA_PATH);

    return retval;
}

static void test_pong_digest(const char * shared_key, const char * hostname, const char * nonce, size_t nonce_size, const char * salt, size_t salt_size, os_sha512 output) {
    unsigned char md[SHA512_DIGEST_LENGTH];
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    EVP_DigestInit(ctx, EVP_sha512());
    EVP_DigestUpdate(ctx, salt, salt_size);
    EVP_DigestUpdate(ctx, hostname, strlen(hostname));
    EVP_DigestUpdate(ctx, nonce, nonce_size);
    EVP_DigestUpdate(ctx, shared_key, strlen(shared_key));
    EVP_DigestFinal(ctx, md, NULL);
    EVP_MD_CTX_free(ctx);
    OS_SHA512_Hex(md, output);
}


typedef struct test_fluent_server_t {
    int sock;
    X509 * cert;
    EVP_PKEY * key;
    const char * shared_key;
    const char * helo_extra_key;
    bool auth_result;
    const char * reason;
    const char * hostname;
} test_fluent_server_t;

/* Fluent collector that completes the handshake and answers with the given PONG fields */
static void * test_fluent_server_run(void * arg) {
    test_fluent_server_t * server = (test_fluent_server_t *)arg;
    static const char nonce[] = "0123456789abcdef";
    SSL_CTX * ctx = SSL_CTX_new(TLS_method());
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_unpacker unp;
    msgpack_unpacked result;
    os_sha512 digest;
    char salt[16] = {0};
    SSL * ssl;
    BIO * bio;
    int read_b;

    SSL_CTX_use_certificate(ctx, server->cert);
    SSL_CTX_use_PrivateKey(ctx, server->key);

    ssl = SSL_new(ctx);
    bio = BIO_new_socket(server->sock, 0);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_accept(ssl) != 1) {
        goto end;
    }

    /* Send HELO */

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pk, 2);
    msgpack_pack_str(&pk, 4);
    msgpack_pack_str_body(&pk, "HELO", 4);
    msgpack_pack_map(&pk, server->helo_extra_key ? 2 : 1);
    msgpack_pack_str(&pk, 5);
    msgpack_pack_str_body(&pk, "nonce", 5);
    msgpack_pack_str(&pk, sizeof(nonce) - 1);
    msgpack_pack_str_body(&pk, nonce, sizeof(nonce) - 1);

    if (server->helo_extra_key) {
        msgpack_pack_str(&pk, strlen(server->helo_extra_key));
        msgpack_pack_str_body(&pk, server->helo_extra_key, strlen(server->helo_extra_key));
        msgpack_pack_true(&pk);
    }

    SSL_write(ssl, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    /* Receive PING and take the salt */

    msgpack_unpacker_init(&unp, 4096);
    msgpack_unpacked_init(&result);
    msgpack_unpacker_reserve_buffer(&unp, 4096);
    read_b = SSL_read(ssl, msgpack_unpacker_buffer(&unp), 4096);

    if (read_b > 0) {
        msgpack_unpacker_buffer_consumed(&unp, read_b);

        if (msgpack_unpacker_next(&unp, &result) == MSGPACK_UNPACK_SUCCESS) {
            memcpy(salt, result.data.via.array.ptr[2].via.str.ptr, sizeof(salt));
        }
    }

    /* Send PONG */

    test_pong_digest(server->shared_key, server->hostname, nonce, sizeof(nonce) - 1, salt, sizeof(salt), digest);

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pk, 5);
    msgpack_pack_str(&pk, 4);
    msgpack_pack_str_body(&pk, "PONG", 4);

    if (server->auth_result) {
        msgpack_pack_true(&pk);
    } else {
        msgpack_pack_false(&pk);
    }

    msgpack_pack_str(&pk, strlen(server->reason));
    msgpack_pack_str_body(&pk, server->reason, strlen(server->reason));
    msgpack_pack_str(&pk, strlen(server->hostname));
    msgpack_pack_str_body(&pk, server->hostname, strlen(server->hostname));
    msgpack_pack_str(&pk, strlen(digest));
    msgpack_pack_str_body(&pk, digest, strlen(digest));

    SSL_write(ssl, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
    msgpack_unpacker_destroy(&unp);

end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return NULL;
}

/* Run the TLS handshake against a local collector that answers with the given PONG fields */
static int test_fluent_hs_tls(wm_fluent_t * fluent, bool auth_result, const char * reason, const char * hostname, const char * helo_extra_key) {
    EVP_PKEY * ca_key = test_tls_gen_key();
    X509 * ca_cert = test_tls_gen_cert(ca_key, "Wazuh Test CA", NULL, NULL, NULL);
    EVP_PKEY * server_key = test_tls_gen_key();
    X509 * server_cert = test_tls_gen_cert(server_key, "fluentd", "DNS:fluentd.internal", ca_cert, ca_key);
    struct timeval timeout = { .tv_sec = 10 };
    test_fluent_server_t server;
    pthread_t thread;
    int sockets[2];
    int retval;
    FILE * fp;

    signal(SIGPIPE, SIG_IGN);

    fp = fopen(TEST_CA_PATH, "w");
    assert_non_null(fp);
    PEM_write_X509(fp, ca_cert);
    fclose(fp);

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    fluent->address = "fluentd.internal";
    fluent->certificate = TEST_CA_PATH;
    fluent->port = 24224;
    fluent->shared_key = "secret_key";
    fluent->user_name = "";
    fluent->user_pass = "";
    fluent->client_sock = sockets[0];

    server.sock = sockets[1];
    server.cert = server_cert;
    server.key = server_key;
    server.shared_key = fluent->shared_key;
    server.helo_extra_key = helo_extra_key;
    server.auth_result = auth_result;
    server.reason = reason;
    server.hostname = hostname;
    assert_int_equal(pthread_create(&thread, NULL, test_fluent_server_run, &server), 0);

    retval = wm_fluent_hs_tls(fluent);

    pthread_join(thread, NULL);

    SSL_free(fluent->ssl);
    fluent->ssl = NULL;
    SSL_CTX_free(fluent->ctx);
    fluent->ctx = NULL;
    fluent->address = NULL;
    fluent->certificate = NULL;
    fluent->shared_key = NULL;
    fluent->user_name = NULL;
    fluent->user_pass = NULL;
    fluent->client_sock = -1;

    close(sockets[0]);
    close(sockets[1]);
    X509_free(server_cert);
    EVP_PKEY_free(server_key);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    unlink(TEST_CA_PATH);

    return retval;
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
    expect_string(__wrap__mdebug2, formatted_msg, "Discarding event from analysisd due to connection issue with 'fluentd_test', No such file or directory. (Abort).");

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


void test_ssl_connect_certificate_name_mismatch(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_any(__wrap__mterror, formatted_msg);

    assert_int_equal(test_tls_connect(data->fluent, "fluentd.internal", "DNS:evil.example.com"), -1);
}

void test_ssl_connect_certificate_name_match(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    assert_int_equal(test_tls_connect(data->fluent, "fluentd.internal", "DNS:fluentd.internal"), 0);
}

void test_check_pong_valid_digest(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    wm_fluent_helo_t helo = { .nonce = "nonce", .nonce_size = 5 };
    wm_fluent_pong_t pong = { .auth_result = 1, .server_hostname = "fluentd.internal" };
    char salt[16] = "0123456789abcde";
    os_sha512 digest;

    data->fluent->shared_key = "secret_key";
    test_pong_digest(data->fluent->shared_key, pong.server_hostname, helo.nonce, helo.nonce_size, salt, sizeof(salt), digest);
    pong.shared_key_hexdigest = digest;

    assert_int_equal(wm_fluent_check_pong(data->fluent, &helo, &pong, salt, sizeof(salt)), 0);
}

void test_check_pong_invalid_digest(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    wm_fluent_helo_t helo = { .nonce = "nonce", .nonce_size = 5 };
    wm_fluent_pong_t pong = { .auth_result = 1, .server_hostname = "fluentd.internal" };
    char salt[16] = "0123456789abcde";
    os_sha512 digest;

    data->fluent->shared_key = "secret_key";
    test_pong_digest("wrong_key", pong.server_hostname, helo.nonce, helo.nonce_size, salt, sizeof(salt), digest);
    pong.shared_key_hexdigest = digest;

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_string(__wrap__mterror, formatted_msg, "Authentication error: the Fluent server did not prove knowledge of the shared key.");

    assert_int_equal(wm_fluent_check_pong(data->fluent, &helo, &pong, salt, sizeof(salt)), -1);
}

void test_check_pong_no_digest(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    wm_fluent_helo_t helo = { .nonce = "nonce", .nonce_size = 5 };
    wm_fluent_pong_t pong = { .auth_result = 1, .server_hostname = "fluentd.internal" };
    char salt[16] = "0123456789abcde";

    data->fluent->shared_key = "secret_key";

    expect_string(__wrap__mterror, tag, "fluent-forward");
    expect_string(__wrap__mterror, formatted_msg, "The Fluent server sent a PONG message with no shared key digest.");

    assert_int_equal(wm_fluent_check_pong(data->fluent, &helo, &pong, salt, sizeof(salt)), -1);
}


void test_sanitize_control_characters(void **state) {
    char * sanitized = wm_fluent_sanitize("line\r\nforged\ttail", 17);

    assert_string_equal(sanitized, "line__forged_tail");
    free(sanitized);
}

void test_sanitize_keeps_printable_characters(void **state) {
    char * sanitized = wm_fluent_sanitize("fluentd.internal", 16);

    assert_string_equal(sanitized, "fluentd.internal");
    free(sanitized);
}

void test_hs_tls_sanitizes_rejection_reason(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mtdebug1, tag, "fluent-forward");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_string(__wrap__mtdebug2, tag, "fluent-forward");
    expect_string(__wrap__mtdebug2, formatted_msg, "Unexpected key: evil__key");

    expect_string(__wrap__mtwarn, tag, "fluent-forward");
    expect_string(__wrap__mtwarn, formatted_msg,
                  "Authentication error: the Fluent server rejected the connection: denied__wazuh-modulesd:fluent-forward: INFO: Connected to host 'forged'");

    assert_int_equal(test_fluent_hs_tls(data->fluent, false,
                                        "denied\r\nwazuh-modulesd:fluent-forward: INFO: Connected to host 'forged'",
                                        "collector", "evil\r\nkey"), -1);
}

void test_hs_tls_sanitizes_server_hostname(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mtdebug1, tag, "fluent-forward");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_string(__wrap__mtinfo, tag, "fluent-forward");
    expect_string(__wrap__mtinfo, formatted_msg,
                  "Connected to host 'collector__wazuh-modulesd:fluent-forward: ERROR: forged' (fluentd.internal:24224)");

    assert_int_equal(test_fluent_hs_tls(data->fluent, true, "",
                                        "collector\r\nwazuh-modulesd:fluent-forward: ERROR: forged", NULL), 0);
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

    /* Test TLS connection to a server whose certificate does not match the configured address */
    cmocka_unit_test_setup_teardown(test_ssl_connect_certificate_name_mismatch, test_setup, test_teardown),
    /* Test TLS connection to a server whose certificate matches the configured address */
    cmocka_unit_test_setup_teardown(test_ssl_connect_certificate_name_match, test_setup, test_teardown),
    /* Test PONG message holding a valid shared key digest */
    cmocka_unit_test_setup_teardown(test_check_pong_valid_digest, test_setup, test_teardown),
    /* Test PONG message holding an invalid shared key digest */
    cmocka_unit_test_setup_teardown(test_check_pong_invalid_digest, test_setup, test_teardown),
    /* Test PONG message holding no shared key digest */
    cmocka_unit_test_setup_teardown(test_check_pong_no_digest, test_setup, test_teardown),

    /* Test sanitization of strings received from the server */
    cmocka_unit_test_setup_teardown(test_sanitize_control_characters, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_sanitize_keeps_printable_characters, test_setup, test_teardown),
    /* Test that the rejection reason cannot forge log entries */
    cmocka_unit_test_setup_teardown(test_hs_tls_sanitizes_rejection_reason, test_setup, test_teardown),
    /* Test that the server hostname cannot forge log entries */
    cmocka_unit_test_setup_teardown(test_hs_tls_sanitizes_server_hostname, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
 * Copyright (C) Wazuh Inc.
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

#include "shared.h"
#include "auth.h"
#include "sec.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/externals/openssl/ssl_lib_wrappers.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* main-server.c is compiled with WAZUH_UNIT_TESTING, which turns its file-scope
 * `static` declarations into externally-linkable ones (see auth.c for the same
 * pattern). g_client_pool, sweep_idle_clients(), handle_ssl_read() and
 * enqueue_pending_key() have no header of their own, so they are declared here directly. */
extern struct client * g_client_pool[AUTH_POOL];
extern void sweep_idle_clients(void);
extern int handle_ssl_read(struct client *client);
extern void enqueue_pending_key(int ret, uint32_t index_client);
extern int authd_test_tls_material(const char *home_path);
extern void authd_apply_debug_option(int cli_debug_level, int test_config);

/* Same minimal reimplementation of keys_init() as test_auth_add.c: it's a
 * file-local helper in auth.c with no header, so every test file that needs a
 * real keystore copies it. */
void keys_init(keystore *keys, key_mode_t key_mode, int save_removed) {
    keys->keytree_id = rbtree_init();
    keys->keytree_ip = rbtree_init();
    keys->keytree_sock = rbtree_init();

    if (!(keys->keytree_id && keys->keytree_ip && keys->keytree_sock)) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->id_counter = 0;
    keys->flags.key_mode = key_mode;
    keys->flags.save_removed = save_removed;

    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);
    w_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);
}

extern struct keynode *queue_insert;
extern struct keynode * volatile *insert_tail;

#define TEST_SLOT 1

time_t __wrap_w_get_monotonic_time(void) {
    return mock_type(time_t);
}

static struct client * make_client(bool handshake_done, time_t connected_at, int read_offset, int write_len) {
    struct client * client;

    os_calloc(1, sizeof(struct client), client);
    client->socket = -1;
    client->index = TEST_SLOT;
    client->is_ipv6 = FALSE;
    client->addr4 = NULL;
    client->ssl = NULL;
    client->handshake_done = handshake_done;
    client->connected_at = connected_at;
    client->read_offset = read_offset;
    client->write_len = write_len;
    strncpy(client->ip, "127.0.0.1", IPSIZE);
    client->read_buffer = NULL;
    client->write_buffer = NULL;
    client->agentname = NULL;
    client->centralized_group = NULL;
    client->new_id = NULL;

    return client;
}

static int teardown_pool(void ** state) {
    for (int i = 1; i < AUTH_POOL; i++) {
        if (g_client_pool[i]) {
            os_free(g_client_pool[i]);
            g_client_pool[i] = NULL;
        }
    }
    return 0;
}

/* setup/teardown for enqueue_pending_key(): a real keystore with two agents
 * (agent-a added first, agent-b second, so agent-a is never the last entry),
 * and a pool client standing in for agent-a's connection. */
static int setup_pending_key(void ** state) {
    config.worker_node = FALSE;

    keys_init(&keys, W_RAW_KEY, 0);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    OS_AddNewAgent(&keys, NULL, "agent-a", "10.0.0.1", NULL, 0);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    OS_AddNewAgent(&keys, NULL, "agent-b", "10.0.0.2", NULL, 0);

    insert_tail = &queue_insert;

    g_client_pool[TEST_SLOT] = make_client(TRUE, 0, 0, 0);
    g_client_pool[TEST_SLOT]->enrollment_ok = true;
    os_strdup("agent-a", g_client_pool[TEST_SLOT]->agentname);
    os_strdup(keys.keyentries[0]->id, g_client_pool[TEST_SLOT]->new_id);

    return 0;
}

static int teardown_pending_key(void ** state) {
    teardown_pool(state);

    struct keynode *cur, *next;
    for (cur = queue_insert; cur; cur = next) {
        next = cur->next;
        os_free(cur->id);
        os_free(cur->name);
        os_free(cur->ip);
        os_free(cur->raw_key);
        os_free(cur->group);
        os_free(cur->reenroll_secret);
        os_free(cur);
    }
    queue_insert = NULL;

    OS_FreeKeys(&keys);

    return 0;
}

/* tests */

static void test_sweep_idle_clients_closes_stale_pre_handshake(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(FALSE, 1000, 0, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Closing idle enrolment connection from 127.0.0.1 (slot 1)");

    sweep_idle_clients();

    assert_null(g_client_pool[TEST_SLOT]);
}

static void test_sweep_idle_clients_skips_recent_connection(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(FALSE, 1000, 0, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT - 1);

    sweep_idle_clients();

    assert_non_null(g_client_pool[TEST_SLOT]);
    assert_false(g_client_pool[TEST_SLOT]->handshake_done);
}

static void test_sweep_idle_clients_skips_completed_handshake_with_response_queued(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(TRUE, 1000, 1, 42);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT + 1000);

    sweep_idle_clients();

    assert_non_null(g_client_pool[TEST_SLOT]);
    assert_true(g_client_pool[TEST_SLOT]->handshake_done);
}

static void test_sweep_idle_clients_closes_completed_handshake_with_no_data(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(TRUE, 1000, 0, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Closing idle enrolment connection from 127.0.0.1 (slot 1)");

    sweep_idle_clients();

    assert_null(g_client_pool[TEST_SLOT]);
}

static void test_sweep_idle_clients_closes_completed_handshake_with_partial_request(void ** state) {
    /* Handshake finished and a byte arrived, but no '\n' yet: process_message() never ran,
     * so write_len is still 0. This is the case that used to stay exempt forever. */
    g_client_pool[TEST_SLOT] = make_client(TRUE, 1000, 1, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Closing idle enrolment connection from 127.0.0.1 (slot 1)");

    sweep_idle_clients();

    assert_null(g_client_pool[TEST_SLOT]);
}

/* handle_ssl_read() */

static void expect_ssl_read(struct client * client, int offset, const char * data, int ret) {
    expect_value(__wrap_SSL_read, ssl, client->ssl);
    expect_value(__wrap_SSL_read, buf, client->read_buffer + offset);
    expect_value(__wrap_SSL_read, num, MAX_SSL_MSG_SIZE - offset);
    will_return(__wrap_SSL_read, data);
    will_return(__wrap_SSL_read, ret);
}

static void expect_ssl_read_drained(struct client * client) {
    expect_value(__wrap_SSL_read, ssl, client->ssl);
    expect_any(__wrap_SSL_read, buf);
    expect_any(__wrap_SSL_read, num);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, -1);
    expect_value(__wrap_SSL_get_error, i, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);
    expect_string(__wrap__mdebug2, formatted_msg, "SSL read in progress for socket=-1");
}

static int teardown_read_client(void ** state) {
    struct client * client = *state;

    os_free(client->read_buffer);
    os_free(client);
    return 0;
}

static struct client * make_read_client(void ** state, int read_offset) {
    struct client * client = make_client(TRUE, 1000, read_offset, 0);

    os_calloc(MAX_SSL_MSG_SIZE + 1, sizeof(char), client->read_buffer);
    *state = client;
    return client;
}

static void test_handle_ssl_read_partial_record_waits_without_error(void ** state) {
    /* A record with no '\n' is an incomplete request, not an error: no merror may be
     * emitted (the wrapper fails the test on an unexpected call), the connection stays
     * open and the bytes are kept for the next read. */
    struct client * client = make_read_client(state, 0);

    expect_ssl_read(client, 0, "OSSEC", 5);
    expect_ssl_read_drained(client);

    assert_int_equal(handle_ssl_read(client), 0);
    assert_int_equal(client->read_offset, 5);
}

static void test_handle_ssl_read_drains_every_short_record(void ** state) {
    /* Edge-triggered epoll: stopping after the first short record would strand the rest
     * until the idle sweep. Every record queued in this burst must be consumed. */
    struct client * client = make_read_client(state, 0);

    expect_ssl_read(client, 0, "OS", 2);
    expect_ssl_read(client, 2, "SE", 2);
    expect_ssl_read(client, 4, "C", 1);
    expect_ssl_read_drained(client);

    assert_int_equal(handle_ssl_read(client), 0);
    assert_int_equal(client->read_offset, 5);
}

static void test_handle_ssl_read_full_buffer_without_newline_closes(void ** state) {
    struct client * client = make_read_client(state, MAX_SSL_MSG_SIZE - 3);

    expect_ssl_read(client, MAX_SSL_MSG_SIZE - 3, "abc", 3);
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Enrollment request from 127.0.0.1 exceeds 69632 bytes without a newline terminator. "
                  "Closing connection.");

    assert_int_equal(handle_ssl_read(client), -1);
    assert_int_equal(client->read_offset, MAX_SSL_MSG_SIZE);
}

/* enqueue_pending_key(): both cases fail with the old `keys.keyentries[keys.keysize - 1]`
 * indexing (PR #39651) because agent-a is never the last entry. */

static void test_enqueue_pending_key_inserts_own_key(void ** state) {
    enqueue_pending_key(1, TEST_SLOT);

    assert_non_null(queue_insert);
    assert_string_equal(queue_insert->name, "agent-a");
    assert_null(g_client_pool[TEST_SLOT]);
}

static void test_enqueue_pending_key_rollback_keeps_other_key(void ** state) {
    expect_string(__wrap__merror, formatted_msg, "SSL write error (-1)");
    expect_string(__wrap__merror, formatted_msg, "Agent key not saved for agent-a");

    enqueue_pending_key(-1, TEST_SLOT);

    assert_int_equal(keys.keysize, 1);
    assert_string_equal(keys.keyentries[0]->name, "agent-b");
    assert_null(g_client_pool[TEST_SLOT]);
}

/* authd_test_tls_material(): what `-t` loads of the port-1515 listener's TLS material. Real OpenSSL on
 * files under a private temporary directory: a self-signed pair generated at setup, its certificate
 * standing in for the agents' CA, plus a text file and the private key as the two wrong CAs. */

static char tls_dir[] = "/tmp/authd_tls_test_XXXXXX";
static char tls_cert[PATH_MAX];
static char tls_key[PATH_MAX];
static char tls_text[PATH_MAX];

static int setup_tls_material(void ** state) {
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    FILE *fp;

    if (!mkdtemp(tls_dir)) {
        return -1;
    }

    snprintf(tls_cert, sizeof(tls_cert), "%s/cert.pem", tls_dir);
    snprintf(tls_key, sizeof(tls_key), "%s/key.pem", tls_dir);
    snprintf(tls_text, sizeof(tls_text), "%s/ca.txt", tls_dir);

    if (pkey = EVP_EC_gen("P-256"), !pkey) {
        return -1;
    }

    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 3600);
    X509_set_pubkey(x509, pkey);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x509), "CN", MBSTRING_ASC, (const unsigned char *)"authd-test", -1, -1, 0);
    X509_set_issuer_name(x509, X509_get_subject_name(x509));
    X509_sign(x509, pkey, EVP_sha256());

    fp = fopen(tls_cert, "w");
    PEM_write_X509(fp, x509);
    fclose(fp);

    fp = fopen(tls_key, "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    fp = fopen(tls_text, "w");
    fputs("not a certificate\n", fp);
    fclose(fp);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    memset(&config.flags, 0, sizeof(config.flags));
    config.flags.remote_enrollment = 1;
    config.flags.legacy_enrollment = 1;
    config.port = 1515;
    os_strdup(DEFAULT_CIPHERS, config.ciphers);
    os_strdup(tls_cert, config.manager_cert);
    os_strdup(tls_key, config.manager_key);
    config.agent_ca = NULL;

    return 0;
}

static int teardown_tls_material(void ** state) {
    os_free(config.ciphers);
    os_free(config.manager_cert);
    os_free(config.manager_key);
    os_free(config.agent_ca);
    unlink(tls_cert);
    unlink(tls_key);
    unlink(tls_text);
    rmdir(tls_dir);
    strcpy(tls_dir, "/tmp/authd_tls_test_XXXXXX");
    return 0;
}

static void test_tls_material_valid_pair_and_ca(void ** state) {
    os_strdup(tls_cert, config.agent_ca);

    expect_string(__wrap__mdebug1, formatted_msg, "Peer verification requested.");
    expect_string(__wrap__mdebug1, formatted_msg, "Returning CTX for server.");

    assert_int_equal(authd_test_tls_material("/var/wazuh-manager"), 0);
}

static void test_tls_material_valid_pair_without_ca(void ** state) {
    expect_string(__wrap__mdebug1, formatted_msg, "Returning CTX for server.");

    assert_int_equal(authd_test_tls_material("/var/wazuh-manager"), 0);
}

static void test_tls_material_text_file_as_ca_fails(void ** state) {
    /* expect_string() keeps the pointer, not a copy: one buffer per expected line */
    char expected_ca[OS_MAXSTR];
    char expected[OS_MAXSTR];

    os_strdup(tls_text, config.agent_ca);

    expect_string(__wrap__mdebug1, formatted_msg, "Peer verification requested.");
    snprintf(expected_ca, sizeof(expected_ca), "Unable to read CA certificate file \"%s\"", tls_text);
    expect_string(__wrap__merror, formatted_msg, expected_ca);
    snprintf(expected, sizeof(expected),
             "SSL context setup failed (certificate '%s', key '%s', CA '%s'): the enrollment listener on port 1515 would not start.",
             tls_cert, tls_key, tls_text);
    expect_string(__wrap__merror, formatted_msg, expected);

    assert_int_equal(authd_test_tls_material("/var/wazuh-manager"), -1);
}

static void test_tls_material_key_as_ca_fails(void ** state) {
    /* expect_string() keeps the pointer, not a copy: one buffer per expected line */
    char expected_ca[OS_MAXSTR];
    char expected[OS_MAXSTR];

    os_strdup(tls_key, config.agent_ca);

    expect_string(__wrap__mdebug1, formatted_msg, "Peer verification requested.");
    snprintf(expected_ca, sizeof(expected_ca), "Unable to read CA certificate file \"%s\"", tls_key);
    expect_string(__wrap__merror, formatted_msg, expected_ca);
    snprintf(expected, sizeof(expected),
             "SSL context setup failed (certificate '%s', key '%s', CA '%s'): the enrollment listener on port 1515 would not start.",
             tls_cert, tls_key, tls_key);
    expect_string(__wrap__merror, formatted_msg, expected);

    assert_int_equal(authd_test_tls_material("/var/wazuh-manager"), -1);
}

/* The start never loads the material when authd or its listener is off, so neither does the test run:
 * the CA here is wrong and no log line is expected. */
static void test_tls_material_skipped_when_authd_disabled(void ** state) {
    os_strdup(tls_text, config.agent_ca);
    config.flags.disabled = 1;

    assert_int_equal(authd_test_tls_material("/var/wazuh-manager"), 0);
}

static void test_tls_material_skipped_without_legacy_listener(void ** state) {
    os_strdup(tls_text, config.agent_ca);
    config.flags.legacy_enrollment = 0;

    assert_int_equal(authd_test_tls_material("/var/wazuh-manager"), 0);
}

/* authd.debug: what the start reads, and with the same range and default, is what -t judges. */
static void expect_authd_debug_read(int value) {
    expect_string(__wrap_getDefine_Int_default, low_name, "debug");
    expect_value(__wrap_getDefine_Int_default, min, 0);
    expect_value(__wrap_getDefine_Int_default, max, 2);
    expect_value(__wrap_getDefine_Int_default, default_val, 0);
    will_return(__wrap_getDefine_Int_default, value);
}

/* The test run reads the option (an out-of-range value exits inside getDefine_Int_default(), so
 * reading it is what makes -t refuse it) but leaves the verbosity alone. */
static void test_debug_option_read_on_test_run(void ** state) {
    (void) state;
    const int before = isDebug();

    expect_authd_debug_read(2);

    authd_apply_debug_option(0, 1);

    assert_int_equal(isDebug(), before);
}

/* A start reads the same option and applies it. */
static void test_debug_option_read_and_applied_on_start(void ** state) {
    (void) state;
    const int before = isDebug();

    expect_authd_debug_read(2);

    authd_apply_debug_option(0, 0);

    assert_int_equal(isDebug(), before + 2);
}

/* -d on the command line wins on both paths: the option is not read (no mock queued, so a read fails). */
static void test_debug_option_skipped_with_cli_debug(void ** state) {
    (void) state;

    authd_apply_debug_option(1, 1);
    authd_apply_debug_option(1, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_handle_ssl_read_partial_record_waits_without_error, teardown_read_client),
        cmocka_unit_test_teardown(test_handle_ssl_read_drains_every_short_record, teardown_read_client),
        cmocka_unit_test_teardown(test_handle_ssl_read_full_buffer_without_newline_closes, teardown_read_client),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_stale_pre_handshake, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_skips_recent_connection, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_skips_completed_handshake_with_response_queued, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_completed_handshake_with_no_data, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_completed_handshake_with_partial_request, teardown_pool),
        cmocka_unit_test_setup_teardown(test_enqueue_pending_key_inserts_own_key, setup_pending_key, teardown_pending_key),
        cmocka_unit_test_setup_teardown(test_enqueue_pending_key_rollback_keeps_other_key, setup_pending_key, teardown_pending_key),
        cmocka_unit_test_setup_teardown(test_tls_material_valid_pair_and_ca, setup_tls_material, teardown_tls_material),
        cmocka_unit_test_setup_teardown(test_tls_material_valid_pair_without_ca, setup_tls_material, teardown_tls_material),
        cmocka_unit_test_setup_teardown(test_tls_material_text_file_as_ca_fails, setup_tls_material, teardown_tls_material),
        cmocka_unit_test_setup_teardown(test_tls_material_key_as_ca_fails, setup_tls_material, teardown_tls_material),
        cmocka_unit_test_setup_teardown(test_tls_material_skipped_when_authd_disabled, setup_tls_material, teardown_tls_material),
        cmocka_unit_test_setup_teardown(test_tls_material_skipped_without_legacy_listener, setup_tls_material, teardown_tls_material),
        cmocka_unit_test(test_debug_option_read_on_test_run),
        cmocka_unit_test(test_debug_option_skipped_with_cli_debug),
        cmocka_unit_test(test_debug_option_read_and_applied_on_start),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

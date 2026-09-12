/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/config/mconf-config_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "sec.h"
#include "enrollment_token.h"
#include "enrollment_token_store.h"
#include "reenroll_verify.h"
#include "../wrappers/wazuh/shared/wazuhdb_queries_op_wrappers.h"

#include "cJSON.h"

/* local_add_clustered() bridges a worker's local-socket "add" request to the master over the
 * cluster. It is declared (non-static) in auth.h and defined in local-server.c; these tests
 * exercise its three outcomes by mocking its only external dependency,
 * w_request_agent_add_clustered(). */

/* authd_lib (see os_auth/CMakeLists.txt) deliberately excludes main-server.c from the unit-test
 * library, since it owns main(). Linking any symbol out of local-server.c.o pulls in the whole
 * object file, including run_local_server()/local_add()/local_remove()/local_get() -- none of
 * which this suite calls -- and those reference globals that normally live in main-server.c.
 * Stub them here purely to satisfy the linker; their values are never exercised. */
volatile int write_pending = 0;
volatile int running = 0;
pthread_mutex_t mutex_keys = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;
void authd_sigblock(void) {}

// STATIC in local-server.c (empty under WAZUH_UNIT_TESTING): the token cases drive the protocol end to end.
char* local_dispatch(const char *input);

/* wraps */

int __wrap_w_request_agent_add_clustered(char *err_response,
                                         const char *name,
                                         const char *ip,
                                         __attribute__((unused)) const char *groups,
                                         __attribute__((unused)) const char *key_hash,
                                         char **id,
                                         char **key,
                                         char **reenroll_secret,
                                         authd_force_options_t *force_options,
                                         const char *agent_id,
                                         const char *token_id,
                                         const char *reenroll_kid,
                                         const char *reenroll_bearer,
                                         int *master_error_code) {
    check_expected(name);
    check_expected(ip);
    // NULL when the enrollment carried no token; the id text otherwise (#38993).
    check_expected(token_id);
    // NULL for a first enrollment; the agent id and its bearer, verbatim, for a re-enrollment (#38993).
    check_expected(reenroll_kid);
    check_expected(reenroll_bearer);

    // Mirrors local_add_clustered()'s contract: no caller-supplied id/key/force is ever
    // forwarded on a worker, and the master's re-enrollment secret is always asked for.
    assert_null(force_options);
    assert_null(agent_id);
    assert_non_null(reenroll_secret);

    int result = mock_type(int);

    if (result == 0) {
        const char *mock_id = mock_ptr_type(const char *);
        const char *mock_key = mock_ptr_type(const char *);
        // "" = a master that sent none (the real function os_strdup()s the empty buffer then).
        const char *mock_secret = mock_ptr_type(const char *);
        os_strdup(mock_id, *id);
        os_strdup(mock_key, *key);
        os_strdup(mock_secret, *reenroll_secret);
    } else {
        int code = mock_type(int);
        if (code > 0) {
            *master_error_code = code;
        }
        const char *message = mock_ptr_type(const char *);
        if (message) {
            strncpy(err_response, message, OS_SIZE_2048 - 1);
        }
    }

    return result;
}

// The C++ bridge over the shared verifier (test_reenroll_verify.c drives the real one): here only its
// verdict matters, and that the master hands it exactly the bearer, the agent id and the row's secret.
int __wrap_w_reenroll_verify(const char *bearer,
                             const char *agent_id,
                             const char *secret_hex,
                             __attribute__((unused)) long now,
                             __attribute__((unused)) int jwt_max_age,
                             __attribute__((unused)) int jwt_clock_skew) {
    check_expected(bearer);
    check_expected(agent_id);
    check_expected(secret_hex);
    return mock_type(int);
}

/* tests */

static void test_local_add_clustered_success(void **state) {
    (void) state;
    cJSON *response;
    cJSON *data;

    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_value(__wrap_w_request_agent_add_clustered, token_id, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_kid, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_bearer, NULL);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "003");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    will_return(__wrap_w_request_agent_add_clustered, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    response = local_add_clustered("agent1", "any", NULL, NULL, NULL, NULL, NULL);
    assert_non_null(response);

    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    data = cJSON_GetObjectItem(response, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "id")->valuestring, "003");
    assert_string_equal(cJSON_GetObjectItem(data, "name")->valuestring, "agent1");
    assert_string_equal(cJSON_GetObjectItem(data, "ip")->valuestring, "any");
    assert_string_equal(cJSON_GetObjectItem(data, "key")->valuestring,
                        "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    // The master's re-enrollment secret (#38993) is handed through verbatim...
    assert_string_equal(cJSON_GetObjectItem(data, "reenroll_secret")->valuestring,
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    cJSON_Delete(response);

    // ...and a master that sent none (an older master) leaves the field out, as before.
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_value(__wrap_w_request_agent_add_clustered, token_id, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_kid, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_bearer, NULL);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "004");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    will_return(__wrap_w_request_agent_add_clustered, "");
    response = local_add_clustered("agent1", "any", NULL, NULL, NULL, NULL, NULL);
    assert_non_null(response);
    data = cJSON_GetObjectItem(response, "data");
    assert_string_equal(cJSON_GetObjectItem(data, "id")->valuestring, "004");
    assert_null(cJSON_GetObjectItem(data, "reenroll_secret"));
    cJSON_Delete(response);
}

static void test_local_add_clustered_business_rejection_preserves_master_code(void **state) {
    (void) state;
    cJSON *response;

    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    // Business rejections forwarded by the master (9008 EDUPNAME here) log at warning, not error.
    expect_any_always(__wrap__mwarn, formatted_msg);
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_value(__wrap_w_request_agent_add_clustered, token_id, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_kid, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_bearer, NULL);
    will_return(__wrap_w_request_agent_add_clustered, -1);
    will_return(__wrap_w_request_agent_add_clustered, 9008);
    will_return(__wrap_w_request_agent_add_clustered, "ERROR: Duplicate name");

    response = local_add_clustered("agent1", "any", NULL, NULL, NULL, NULL, NULL);
    assert_non_null(response);

    // The master's own numeric code (9008, Duplicate name) must be surfaced verbatim --
    // not collapsed into the generic 9016 -- and the redundant "ERROR: " prefix stripped.
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9008);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Duplicate name");

    cJSON_Delete(response);
}

static void test_local_add_clustered_transport_failure_maps_to_9016(void **state) {
    (void) state;
    cJSON *response;

    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_value(__wrap_w_request_agent_add_clustered, token_id, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_kid, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_bearer, NULL);
    will_return(__wrap_w_request_agent_add_clustered, -2);
    will_return(__wrap_w_request_agent_add_clustered, 0); // master_error_code left untouched
    will_return(__wrap_w_request_agent_add_clustered, "ERROR: Cannot communicate with master");

    response = local_add_clustered("agent1", "any", NULL, NULL, NULL, NULL, NULL);
    assert_non_null(response);

    // No well-formed business code came back -- transport failure and a malformed/unparseable
    // master response are indistinguishable from here, and both map to the new 9016.
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9016);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring,
                        "Cannot communicate with master node");

    cJSON_Delete(response);
}

/* STATIC in local-server.c, visible here under WAZUH_UNIT_TESTING. Guards the one invariant every
 * caller must satisfy: the name has to survive a round trip through client.keys' line format. */
int is_storable_agent_name(const char *name);

/* A caller-supplied key that is not 64 lowercase hex chars is refused up front with 9019, before any
 * keystore lookup: stored as-is it would only fail later, on every request, as an unusable key. */
static void test_local_add_rejects_a_malformed_explicit_key(void **state) {
    (void) state;
    cJSON *response;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    response = local_add(NULL, "agent1", "any", NULL, "2b7e151628aed2a6abf7158809cf4f3c", NULL, &config.force_options);
    assert_non_null(response);
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9019);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Invalid agent key");
    cJSON_Delete(response);

    response = local_add(NULL, "agent1", "any", NULL,
                         "0030557A9FC4E90E33587DA2C7EC11365B80A5CAEF14395E83A8CDF2173C61FF", NULL, &config.force_options);
    assert_non_null(response);
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9019);
    cJSON_Delete(response);
}

/* A caller-supplied id outside [1, INT32_MAX], or equal to 0, is
 * refused up front with 9020, before any keystore lookup */
static void test_local_add_rejects_an_out_of_range_or_reserved_id(void **state) {
    (void) state;
    cJSON *response;
    const char *invalid_ids[] = {"2147483648", "4294967296", "0", "000", "abc"};
    size_t i;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    for (i = 0; i < sizeof(invalid_ids) / sizeof(invalid_ids[0]); i++) {
        response = local_add(invalid_ids[i], "agent1", "any", NULL, NULL, NULL, &config.force_options);
        assert_non_null(response);
        assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9020);
        assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Invalid agent ID");
        cJSON_Delete(response);
    }
}

static void test_storable_agent_name_accepts_ordinary_names(void **state) {
    (void) state;

    assert_int_equal(is_storable_agent_name("agent1"), 1);
    assert_int_equal(is_storable_agent_name("web-01.example.com"), 1);
    assert_int_equal(is_storable_agent_name("host_name.2"), 1);
}

static void test_storable_agent_name_accepts_names_os_isvalidname_rejects(void **state) {
    (void) state;

    /* The point of not reusing OS_IsValidName(): the API's contract is `^[\w\-.%]+$` with no
     * minimum length, so these have always been accepted here and corrupt nothing. */
    assert_int_equal(is_storable_agent_name("a"), 1);          // single character
    assert_int_equal(is_storable_agent_name("100%cpu"), 1);    // '%' is outside OS_IsValidName()
    assert_int_equal(is_storable_agent_name(".hidden"), 1);    // leading '.'
}

static void test_storable_agent_name_rejects_whitespace_and_control_bytes(void **state) {
    (void) state;

    /* client.keys is whitespace-delimited: any of these splits the name into extra fields and
     * shifts every later column, leaving the agent with a bogus IP and an undecodable key. */
    assert_int_equal(is_storable_agent_name("web 01"), 0);
    assert_int_equal(is_storable_agent_name("web\t01"), 0);
    assert_int_equal(is_storable_agent_name("web\n01"), 0);
    assert_int_equal(is_storable_agent_name("web\r01"), 0);
    assert_int_equal(is_storable_agent_name("web\x01" "01"), 0);
    assert_int_equal(is_storable_agent_name("web\x7f" "01"), 0);
    assert_int_equal(is_storable_agent_name(" leading"), 0);
    assert_int_equal(is_storable_agent_name("trailing "), 0);
}

static void test_storable_agent_name_rejects_removed_entry_markers(void **state) {
    (void) state;

    /* A leading '#'/'!' is the removed-entry marker: readers skip the line, dropping the agent. */
    assert_int_equal(is_storable_agent_name("#agent"), 0);
    assert_int_equal(is_storable_agent_name("!agent"), 0);

    /* Only in the FIRST position -- these are storable. */
    assert_int_equal(is_storable_agent_name("agent#1"), 1);
    assert_int_equal(is_storable_agent_name("agent!1"), 1);
}

static void test_storable_agent_name_rejects_empty_and_overlong(void **state) {
    (void) state;
    char overlong[130];
    char at_limit[129];

    assert_int_equal(is_storable_agent_name(NULL), 0);
    assert_int_equal(is_storable_agent_name(""), 0);

    memset(at_limit, 'a', 128);
    at_limit[128] = '\0';
    assert_int_equal(is_storable_agent_name(at_limit), 1); // exactly 128 is allowed

    memset(overlong, 'a', 129);
    overlong[129] = '\0';
    assert_int_equal(is_storable_agent_name(overlong), 0);
}

/* STATIC in local-server.c, visible here under WAZUH_UNIT_TESTING. Keeps a non-string JSON value
 * (valuestring is NULL for those) from becoming a NULL deref in the dispatcher. */
int get_optional_string_arg(cJSON *arguments, const char *key, char **out);

static void test_optional_string_arg_absent_or_null_means_not_supplied(void **state) {
    (void) state;
    cJSON *arguments = cJSON_Parse("{\"other\": \"x\", \"key\": null}");
    char *out = (char *)0x1; // poisoned: the function must always write *out

    assert_non_null(arguments);

    assert_int_equal(get_optional_string_arg(arguments, "missing", &out), 0);
    assert_null(out);

    out = (char *)0x1;
    /* Explicit null is how a client spells "unset": absent, not a type error. */
    assert_int_equal(get_optional_string_arg(arguments, "key", &out), 0);
    assert_null(out);

    cJSON_Delete(arguments);
}

static void test_optional_string_arg_returns_string_values(void **state) {
    (void) state;
    cJSON *arguments = cJSON_Parse("{\"id\": \"003\", \"empty\": \"\"}");
    char *out = NULL;

    assert_non_null(arguments);

    assert_int_equal(get_optional_string_arg(arguments, "id", &out), 0);
    assert_string_equal(out, "003");

    assert_int_equal(get_optional_string_arg(arguments, "empty", &out), 0);
    assert_string_equal(out, "");

    cJSON_Delete(arguments);
}

static void test_optional_string_arg_rejects_non_string_types(void **state) {
    (void) state;
    cJSON *arguments = cJSON_Parse("{\"n\": 5, \"b\": true, \"o\": {}, \"a\": []}");
    char *out = NULL;

    assert_non_null(arguments);

    /* Each leaves valuestring NULL. Rejecting rather than treating them as absent matters most for
     * "id"/"key", where dropping a malformed value would add a different agent and report success. */
    assert_int_equal(get_optional_string_arg(arguments, "n", &out), -1);
    assert_null(out);
    assert_int_equal(get_optional_string_arg(arguments, "b", &out), -1);
    assert_null(out);
    assert_int_equal(get_optional_string_arg(arguments, "o", &out), -1);
    assert_null(out);
    assert_int_equal(get_optional_string_arg(arguments, "a", &out), -1);
    assert_null(out);

    cJSON_Delete(arguments);
}


// ---------------------------------------------------------------- enrollment tokens (#38993)
//
// The store and the X509 checks run for real on files under a private temporary directory (the
// same way test_purge_journal.c drives the deletion journal); only the `remote` section of the
// configuration is handed in through __wrap_w_mconf_section, pointing at those files. Certificates
// are the frozen E4 fixtures: the CA whose SPKI pin is 6091dc36...0aa2, the leaf it signed for
// `wazuh-1` (SAN 127.0.0.1, wazuh-manager, localhost, host.docker.internal, wazuh-1) and a
// self-signed certificate that only names loopback.

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDSzCCAjOgAwIBAgIUJP7/SAPLSdxLbWKDzjDp88k4AAAwDQYJKoZIhvcNAQEL\n"
    "BQAwNTEOMAwGA1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApD\n"
    "YWxpZm9ybmlhMB4XDTI2MDQxNDEzNTAzN1oXDTM2MDQxMTEzNTAzN1owNTEOMAwG\n"
    "A1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApDYWxpZm9ybmlh\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQFyQMfZg9BkCde6Sa6O\n"
    "8834rzeI81clYfEuDjflnwUTyp6BwHZTZ4F/cOBchKt2ZtnNR7Vx2wU5muDdF1QR\n"
    "xnzDEV3vqETcGN7dxarYQtNCuvi/V0Zm0rme9Q9tW8u4iVwhva/jB5VJuDxlREfH\n"
    "RL9pcjf9Dmvr1A9QRBgN0gsofAPri6gi8fLOfqddyNhLDHVd4BhYvB4wgxN5gXs/\n"
    "KOCPGBhIuBb7BbdZDXMm+1PrBebZ1PgL1NEN4dtLQEq7/JXsJpeh8HGsH+WA91V7\n"
    "HRI6O2nsT7YEiw4lGK/DfNroPrQ+G5Qq+Ouy5Z+8NnWV/WJu6tsv2TtqVCNG2Ift\n"
    "vwIDAQABo1MwUTAdBgNVHQ4EFgQU2CaFfHEP1s0zMeo5QL/yLQl69EAwHwYDVR0j\n"
    "BBgwFoAU2CaFfHEP1s0zMeo5QL/yLQl69EAwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n"
    "hkiG9w0BAQsFAAOCAQEAW2F0iQS92w4Q1im3ijS9qg2rnLuzrFeLkbhDNc1P4UIR\n"
    "Wst/FKUV0MsYBvbotf2gNWSZEsKqDV5kYB4Ad1RUFIJGq0HEnrLEIgXZDgUkHaLQ\n"
    "2FXSWDbq4Q3tROB2SiXk61Md6HOvfgT4/MYx/IoZB3fE8pP0vINA/TPw6WZsbz+K\n"
    "93PEjHaMASUlUoowImFgV4uxzgfVWYWcUwi+IUehMqBgU3apvZ1ntUgw8CZTR7BQ\n"
    "E3f6uPqaFJnQg2NZpc0bST6iF/bwKemDhdtd0pwgTivB3RrgSDjBqcR0DGTCKydU\n"
    "gifB+SqxOI0UFNS5zvIQzUTRxMVDcdnB4NnkcZ/CBQ==\n"
    "-----END CERTIFICATE-----\n";

static const char LEAF_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIID2DCCAsCgAwIBAgIUQcNO9z95jw8UN2qvaK01c2ct7b0wDQYJKoZIhvcNAQEL\n"
    "BQAwNTEOMAwGA1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApD\n"
    "YWxpZm9ybmlhMB4XDTI2MDkwNzIzMDgyMloXDTM2MDkwNDIzMDgyMlowVDELMAkG\n"
    "A1UEBhMCVVMxEzARBgNVBAcMCkNhbGlmb3JuaWExDjAMBgNVBAoMBVdhenVoMQ4w\n"
    "DAYDVQQLDAVXYXp1aDEQMA4GA1UEAwwHd2F6dWgtMTCCASIwDQYJKoZIhvcNAQEB\n"
    "BQADggEPADCCAQoCggEBAMvfNwpc9p1Jle9xYGqevBKluw8mM2zMJTsCuIFTLkPF\n"
    "dPs+LJTPLsALsVq7up0CZidtjliywLumwzC+oKWp1nPC6UoQb6M5jvtl0VuVHvKB\n"
    "j1jSGRej886pggeytBdPO6Cp2todUtLvHM+uwseb4qtyjEQutk6CbEaFpkngGsCB\n"
    "/NZ4kOL1GQhnq2raT3B/AlsW8RN26iJikBhrHRaqqqGLRFa7XYj39wjPtx2Urs4p\n"
    "qkQNSgR+xtDYCkNX5PHdzKiMmdWwoLZIwPxMG3RSB0ixEUQO8DFtOKvk4WHoeKoU\n"
    "3wxkAhofWJbM2S5HbVOH9cnewyzNmvWxBJYG8aI2qo0CAwEAAaOBwDCBvTAfBgNV\n"
    "HSMEGDAWgBTYJoV8cQ/WzTMx6jlAv/ItCXr0QDAdBgNVHQ4EFgQU8hFY3dAJ/GsP\n"
    "PKyzLSDkb51VonkwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l\n"
    "BAwwCgYIKwYBBQUHAwEwSAYDVR0RBEEwP4cEfwAAAYINd2F6dWgtbWFuYWdlcoIJ\n"
    "bG9jYWxob3N0ghRob3N0LmRvY2tlci5pbnRlcm5hbIIHd2F6dWgtMTANBgkqhkiG\n"
    "9w0BAQsFAAOCAQEAWv+qe+VgCsESlg8ubbx7Ftzci0Wco8x399OLanQuKvp8560k\n"
    "nf0T5+kghdj6KxRshgTmVXgEpd1G9tiVFk2z2phy90LGgat2HYwzaIfzuA7DqbyM\n"
    "v5DNnF7UcqhRC5WOL3XDb2zWQMfYScyvUAF58B1MEFPATkdi6zN6/0yroX9B6SLe\n"
    "iPTDEB8jFG9R6qtMYftP+7ZOacKo0Fy0rRdhlQZNl1i5gunUWrpD2w+9EYfYDrXn\n"
    "MykvRq++INuyYbizQMFYSHiYmjpm7XJwlgH1F8p5YxxSs0RagtH0ZERlC8yv7NEK\n"
    "cdIcE8DrGEViL31/r8a6SCRb1c8Tdi7ukLQCXg==\n"
    "-----END CERTIFICATE-----\n";

static const char LOOPBACK_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDQDCCAiigAwIBAgIUThyXoTqzjTsSr+M69T0+JScLXu8wDQYJKoZIhvcNAQEL\n"
    "BQAwGDEWMBQGA1UEAwwNbG9vcGJhY2stb25seTAeFw0yNjA5MDgwMjI0MzJaFw0z\n"
    "NjA5MDUwMjI0MzJaMBgxFjAUBgNVBAMMDWxvb3BiYWNrLW9ubHkwggEiMA0GCSqG\n"
    "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDq+eTb7H0adqFTdCDrNvie0ev96Lyp8Ylq\n"
    "dJ2Z4XsVxuwktn2HiSjwVyHy5VSaXwMcgv2Rruvi6e5Qd8vohic9+n134KKOmdF2\n"
    "yC3WwACxncNJ7NFHnAwhxJ/Rr/v0pjzKPwlL0p4HvdlpU44C3jH9FMeO0hpWnmhd\n"
    "9Kkdu3ddBl7EelF3Ci4JssrDfJNZeCVlmA5fvSZm4K8OGVlZ1ey8pLsvYyiUnDEp\n"
    "Y0/9ycSnK8Qq2Wd8S4OREozjOBIyvtjEtboFGZ0ZqaNeL08bRJVAX1iN95bfMxps\n"
    "PG4ZFYe30CGnDcmJwequYqISProAdzOh7qu0paABUqPYIDgsiY4dAgMBAAGjgYEw\n"
    "fzAdBgNVHQ4EFgQUOhrcgGqECnVp3LH1+Lwio2kaySQwHwYDVR0jBBgwFoAUOhrc\n"
    "gGqECnVp3LH1+Lwio2kaySQwDwYDVR0TAQH/BAUwAwEB/zAsBgNVHREEJTAjggls\n"
    "b2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQAD\n"
    "ggEBADvvvKOjfrZLUneG7igz8rZgKa8a0+TxUYDr/3524zX+tlalDpB9JAhicYe+\n"
    "gfm47kKn91UM07MT0X25iln5EfYA2gCWTF/4OTr+L+6ISIQDhbgxh5FmPworp7tT\n"
    "eDP5CDhsutAzbTCsnEZw9pa/E2QK6CkgIwipWEnKwit0VaXVr/y+M0d6szbPBuS9\n"
    "sMgW5tGQkTdhnsnrrOwuTrGjwqyJa25zM+a53gRi0C07h/2b+5a4oguqAQT0BkHN\n"
    "T5quif12xKlcTs7Mlp/MpPgf4JNyiA6SVgeHqN2PFzph62mm+UIlEh8LX9MZlubo\n"
    "suHg+PvT3ygd27X96wMZ11OhRYI=\n"
    "-----END CERTIFICATE-----\n";

#define TOKEN_PIN_HEX "6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2"
#define TOKENS_FILE "etc/enrollment_tokens.json"
#define IDENTITY_JOURNAL_PATH "queue/authd/pending-identities"
#define LEAF_FILE "etc/certs/remoted.pem"
#define CA_FILE "etc/certs/root-ca.pem"
#define LOOPBACK_FILE "etc/certs/loopback.pem"

// The writer queue a successful add appends to: its tail pointers are initialised in main(), which
// authd_lib does not carry (README §Layout), so the fixture does it, like test_auth_add.c.
extern struct keynode *queue_insert;
extern struct keynode *queue_remove;
extern struct keynode * volatile *insert_tail;
extern struct keynode * volatile *remove_tail;

static void free_keynode_queue(struct keynode **queue) {
    struct keynode *node = *queue;
    while (node) {
        struct keynode *next = node->next;
        free(node->id);
        free(node->name);
        free(node->ip);
        free(node->raw_key);
        free(node->group);
        free(node->reenroll_secret);
        free(node);
        node = next;
    }
    *queue = NULL;
}

static char token_env_dir[] = "/tmp/authd_tokens_XXXXXX";
static char token_env_cwd[4096];

static void write_file(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    assert_true(fputs(text, fp) >= 0);
    assert_int_equal(fclose(fp), 0);
}

static void token_keys_init(void) {
    keys.keytree_id = rbtree_init();
    keys.keytree_ip = rbtree_init();
    keys.keytree_sock = rbtree_init();
    assert_non_null(keys.keytree_id);
    assert_non_null(keys.keytree_ip);
    assert_non_null(keys.keytree_sock);
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.flags.key_mode = W_RAW_KEY;
    keys.flags.save_removed = 0;
    os_calloc(1, sizeof(keyentry), keys.keyentries[keys.keysize]);
    w_mutex_init(&keys.keyentries[keys.keysize]->mutex, NULL);
}

static int setup_token_env(void **state) {
    (void)state;
    assert_non_null(getcwd(token_env_cwd, sizeof(token_env_cwd)));
    assert_non_null(mkdtemp(token_env_dir));
    assert_int_equal(chdir(token_env_dir), 0);
    assert_int_equal(mkdir("etc", 0770), 0);
    assert_int_equal(mkdir("etc/certs", 0770), 0);
    // Every add and every rotation journals its credential before answering (issue #39078, H03),
    // so without this directory the whole suite would answer 9031.
    assert_int_equal(mkdir("queue", 0770), 0);
    assert_int_equal(mkdir("queue/authd", 0750), 0);
    identity_journal_init(IDENTITY_JOURNAL_PATH);
    write_file(LEAF_FILE, LEAF_PEM);
    write_file(CA_FILE, CA_PEM);
    write_file(LOOPBACK_FILE, LOOPBACK_PEM);
    token_keys_init();
    queue_insert = NULL;
    queue_remove = NULL;
    insert_tail = &queue_insert;
    remove_tail = &queue_remove;
    config.worker_node = FALSE;
    config.max_agents = 0;
    // An empty, valid store on disk from the start: every later write rewrites an existing file
    // (TempFile() logs FSTAT_ERROR at debug level when the target does not exist yet) and the one
    // load log is consumed right here, so the cases only declare what their own paths emit.
    write_file(TOKENS_FILE, "{\"version\":1,\"tokens\":[]}\n");
    etoken_store_init(TOKENS_FILE);
    expect_any(__wrap__mdebug1, formatted_msg);
    assert_int_equal(etoken_store_load(), 0);
    return 0;
}

static int teardown_token_env(void **state) {
    (void)state;
    etoken_store_free();
    OS_FreeKeys(&keys);
    free_keynode_queue(&queue_insert);
    free_keynode_queue(&queue_remove);
    insert_tail = &queue_insert;
    remove_tail = &queue_remove;
    identity_journal_init(NULL);
    unlink(IDENTITY_JOURNAL_PATH);
    rmdir("queue/authd");
    rmdir("queue");
    unlink(TOKENS_FILE);
    unlink(LEAF_FILE);
    unlink(CA_FILE);
    unlink(LOOPBACK_FILE);
    rmdir("etc/certs");
    rmdir("etc");
    assert_int_equal(chdir(token_env_cwd), 0);
    rmdir(token_env_dir);
    return 0;
}

// Every log line the code under test emits must be declared (see the README §Tests), and an
// "always" expectation that is never reached fails the case too, so each case declares exactly
// the severities its paths emit -- the wording is not what these cases pin. Sources: a mint logs
// minfo; a 9025 refusal mwarn (plus mint_prepare's mwarn for an IP address); every `goto fail`
// in local_dispatch() merror; the store logs mdebug2 on a consumed/released use and mdebug1 on
// a refused one or an unknown id; local_add() logs mdebug2 and minfo.
#define EXPECT_LOG_DEBUG1() expect_any_always(__wrap__mdebug1, formatted_msg)
#define EXPECT_LOG_DEBUG2() expect_any_always(__wrap__mdebug2, formatted_msg)
#define EXPECT_LOG_INFO()   expect_any_always(__wrap__minfo, formatted_msg)
#define EXPECT_LOG_WARN()   expect_any_always(__wrap__mwarn, formatted_msg)
#define EXPECT_LOG_ERROR()  expect_any_always(__wrap__merror, formatted_msg)

// The `remote` section the mint reads: one fresh object per call, the mint owns and frees it.
static void expect_remote(const char *cert, const char *ca, int port, const char *prefix) {
    cJSON *remote = cJSON_CreateObject();
    cJSON *https = cJSON_AddObjectToObject(remote, "https");
    cJSON_AddNumberToObject(https, "port", port);
    cJSON_AddStringToObject(https, "global_prefix", prefix);
    cJSON_AddStringToObject(https, "certificate", cert);
    cJSON_AddStringToObject(https, "ca_certificate", ca);
    expect_string(__wrap_w_mconf_section, section, "remote");
    will_return(__wrap_w_mconf_section, remote);
}

static void expect_default_remote(void) {
    expect_remote(LEAF_FILE, CA_FILE, 1517, "/wazuh-manager/");
}

static cJSON *dispatch(const char *request) {
    char *output = local_dispatch(request);
    assert_non_null(output);
    cJSON *response = cJSON_Parse(output);
    free(output);
    assert_non_null(response);
    return response;
}

static int response_error(cJSON *response) {
    cJSON *error = cJSON_GetObjectItem(response, "error");
    assert_true(cJSON_IsNumber(error));
    return error->valueint;
}

static const char *data_string(cJSON *response, const char *key) {
    cJSON *item = cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), key);
    assert_true(cJSON_IsString(item));
    return item->valuestring;
}

// Mints with the default listener and returns the response (error 0 asserted).
static cJSON *mint(const char *arguments_json) {
    char request[2048];
    snprintf(request, sizeof(request), "{\"function\":\"token_create\",\"arguments\":%s}", arguments_json);
    expect_default_remote();
    cJSON *response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    return response;
}

static unsigned int uses_on_disk(const char *id) {
    cJSON *file = json_fread(TOKENS_FILE, 0);
    assert_non_null(file);
    cJSON *tokens = cJSON_GetObjectItem(file, "tokens");
    cJSON *token = NULL;
    unsigned int uses = UINT_MAX;
    cJSON_ArrayForEach(token, tokens) {
        cJSON *item = cJSON_GetObjectItem(token, "id");
        if (cJSON_IsString(item) && strcmp(item->valuestring, id) == 0) {
            uses = (unsigned int)cJSON_GetObjectItem(token, "uses")->valueint;
        }
    }
    cJSON_Delete(file);
    assert_int_not_equal(uses, UINT_MAX);
    return uses;
}

static void test_token_create_ok(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    time_t before = time(NULL);
    cJSON *response = mint("{\"address\":\"wazuh-1\",\"description\":\"ci\"}");

    assert_string_equal(data_string(response, "adr"), "wazuh-1");
    assert_string_equal(data_string(response, "pin_hex"), TOKEN_PIN_HEX);
    assert_int_equal(strlen(data_string(response, "id")), ETOKEN_ID_CHARS);
    cJSON *expires = cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "expires");
    assert_true(cJSON_IsNumber(expires));
    assert_in_range((long)expires->valuedouble, (long)before + ETOKEN_DEFAULT_TTL, (long)before + ETOKEN_DEFAULT_TTL + 5);

    // The token text is the E4 codec's: adr, pin and id||secret round-trip.
    w_etoken_t token;
    assert_int_equal(w_etoken_decode(data_string(response, "token"), &token), ETOKEN_OK);
    assert_string_equal(token.adr, "wazuh-1");
    assert_true(token.has_pin);
    assert_true(token.has_key);
    char pin_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(pin_hex + 2 * i, 3, "%02x", token.pin[i]);
    }
    assert_string_equal(pin_hex, TOKEN_PIN_HEX);
    char *id_b64 = w_b64url_encode(token.id, W_ETOKEN_ID_BYTES);
    assert_string_equal(id_b64, data_string(response, "id"));
    free(id_b64);
    w_etoken_free(&token);
    assert_int_equal(uses_on_disk(data_string(response, "id")), 0);
    cJSON_Delete(response);
}

static void test_token_create_refusals_9025(void **state) {
    (void)state;
    EXPECT_LOG_WARN();
    int before = etoken_store_count();
    struct {
        const char *cert;
        const char *ca;
        const char *address;
        const char *detail;
    } cases[] = {
        {LEAF_FILE, CA_FILE, "evil", "SAN"},
        {LOOPBACK_FILE, CA_FILE, "localhost", "loopback"},
        {LEAF_FILE, LOOPBACK_FILE, "wazuh-1", "does not sign"},
        {LEAF_FILE, "etc/certs/missing-ca.pem", "wazuh-1", "ca_certificate"},
        {"etc/certs/missing-leaf.pem", CA_FILE, "wazuh-1", "listener certificate"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char request[512];
        snprintf(request, sizeof(request), "{\"function\":\"token_create\",\"arguments\":{\"address\":\"%s\"}}", cases[i].address);
        expect_remote(cases[i].cert, cases[i].ca, 1517, "/wazuh-manager/");
        cJSON *response = dispatch(request);
        assert_int_equal(response_error(response), 9025);
        cJSON *message = cJSON_GetObjectItem(response, "message");
        assert_true(cJSON_IsString(message));
        assert_non_null(strstr(message->valuestring, "Enrollment token refused: "));
        assert_non_null(strstr(message->valuestring, cases[i].detail));
        cJSON_Delete(response);
    }
    // Nothing was minted and the store was not touched.
    assert_int_equal(etoken_store_count(), before);
}

static void test_token_create_ip_warns_and_overrides(void **state) {
    (void)state;
    EXPECT_LOG_WARN();
    EXPECT_LOG_INFO();
    cJSON *response = mint("{\"address\":\"127.0.0.1\",\"port\":8443,\"prefix\":\"gw\"}");
    assert_string_equal(data_string(response, "adr"), "127.0.0.1:8443/gw");
    cJSON_Delete(response);

    // The configured prefix and port are what the mint writes when the caller gives none: a
    // manager serving no prefix yields the explicit "host/" form, the default port is dropped.
    expect_remote(LEAF_FILE, CA_FILE, 1517, "/");
    response = dispatch("{\"function\":\"token_create\",\"arguments\":{\"address\":\"wazuh-1\"}}");
    assert_int_equal(response_error(response), 0);
    assert_string_equal(data_string(response, "adr"), "wazuh-1/");
    cJSON_Delete(response);
}

static void test_token_create_embed_ca_no_credential(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    cJSON *response = mint("{\"address\":\"wazuh-1\",\"embed_ca\":true,\"no_credential\":true,\"max_uses\":7}");
    assert_null(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "pin_hex"));

    w_etoken_t token;
    assert_int_equal(w_etoken_decode(data_string(response, "token"), &token), ETOKEN_OK);
    assert_false(token.has_pin);
    assert_false(token.has_key);
    assert_non_null(token.ca_pem);
    // The certificate, re-serialized from the parsed object rather than copied out of the file.
    // Byte-identical here because the fixture's file IS just that certificate.
    assert_string_equal(token.ca_pem, CA_PEM);
    w_etoken_free(&token);
    cJSON_Delete(response);
}

static void test_token_create_embed_ca_never_carries_a_private_key(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    // The misprovisioned input of issue #39078 (H01): the CA and its private key in one file. What
    // the operator asked to embed is the trust anchor, and that is all that may travel.
    char *combined = NULL;
    os_calloc(strlen(CA_PEM) + 128, sizeof(char), combined);
    strcpy(combined, CA_PEM);
    strcat(combined, "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----\n");
    write_file(CA_FILE, combined);

    cJSON *response = mint("{\"address\":\"wazuh-1\",\"embed_ca\":true}");
    assert_int_equal(response_error(response), 0);

    w_etoken_t token;
    assert_int_equal(w_etoken_decode(data_string(response, "token"), &token), ETOKEN_OK);
    assert_non_null(token.ca_pem);
    assert_non_null(strstr(token.ca_pem, "BEGIN CERTIFICATE"));
    assert_null(strstr(token.ca_pem, "PRIVATE KEY"));
    w_etoken_free(&token);
    cJSON_Delete(response);

    write_file(CA_FILE, CA_PEM);
    os_free(combined);
}

static void test_token_create_embed_ca_accepts_a_bundle_signed_by_its_second_certificate(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    // A bundle whose signer is NOT the first certificate. Reading only the first one -- what
    // w_x509_load_pem() does -- refused this mint with "ca does not sign the listener certificate".
    char *bundle = NULL;
    os_calloc(strlen(LOOPBACK_PEM) + strlen(CA_PEM) + 1, sizeof(char), bundle);
    strcpy(bundle, LOOPBACK_PEM);
    strcat(bundle, CA_PEM);
    write_file(CA_FILE, bundle);

    cJSON *response = mint("{\"address\":\"wazuh-1\",\"embed_ca\":true}");
    assert_int_equal(response_error(response), 0);

    w_etoken_t token;
    assert_int_equal(w_etoken_decode(data_string(response, "token"), &token), ETOKEN_OK);
    assert_non_null(token.ca_pem);
    assert_non_null(strstr(token.ca_pem, "BEGIN CERTIFICATE"));
    w_etoken_free(&token);
    cJSON_Delete(response);

    write_file(CA_FILE, CA_PEM);
    os_free(bundle);
}

static void test_token_create_bad_arguments(void **state) {
    (void)state;
    EXPECT_LOG_ERROR();
    // No address: 9004 No such argument. A wrongly typed optional: 9002 Parsing JSON input.
    cJSON *response = dispatch("{\"function\":\"token_create\",\"arguments\":{\"ttl\":60}}");
    assert_int_equal(response_error(response), 9004);
    cJSON_Delete(response);
    response = dispatch("{\"function\":\"token_create\",\"arguments\":{\"address\":\"wazuh-1\",\"port\":\"8443\"}}");
    assert_int_equal(response_error(response), 9002);
    cJSON_Delete(response);
    response = dispatch("{\"function\":\"token_create\",\"arguments\":{\"address\":\"wazuh-1\",\"embed_ca\":\"yes\"}}");
    assert_int_equal(response_error(response), 9002);
    cJSON_Delete(response);
    response = dispatch("{\"function\":\"token_create\"}");
    assert_int_equal(response_error(response), 9004);
    cJSON_Delete(response);
}

static void test_token_verbs_on_worker_9015(void **state) {
    (void)state;
    EXPECT_LOG_ERROR();
    config.worker_node = TRUE;
    // No __wrap_w_mconf_section expectation: a worker must refuse before reading anything.
    cJSON *response = dispatch("{\"function\":\"token_create\",\"arguments\":{\"address\":\"wazuh-1\"}}");
    assert_int_equal(response_error(response), 9015);
    cJSON_Delete(response);
    response = dispatch("{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"AAECAwQFBgcICQoLDA0ODw\"}}");
    assert_int_equal(response_error(response), 9015);
    cJSON_Delete(response);
    // Listing is read-only: the replica answers.
    response = dispatch("{\"function\":\"token_list\"}");
    assert_int_equal(response_error(response), 0);
    assert_true(cJSON_IsArray(cJSON_GetObjectItem(response, "data")));
    cJSON_Delete(response);
    config.worker_node = FALSE;
}

/* The store outlives a case: these three read what is there first and assert on the change, not on
 * absolute counts -- the suite mints tokens all the way through and the fixture keeps the file. */
static int token_list_size(void) {
    cJSON *response = dispatch("{\"function\":\"token_list\"}");
    int size = cJSON_GetArraySize(cJSON_GetObjectItem(response, "data"));

    cJSON_Delete(response);

    return size;
}

static void test_token_purge_removes_and_reports(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    // Two tokens, one of them revoked: the purge takes the revoked one and leaves the other.
    cJSON *keep = mint("{\"address\":\"wazuh-1\",\"description\":\"stays\"}");
    cJSON *drop = mint("{\"address\":\"wazuh-1\",\"description\":\"goes\"}");
    char keep_id[ETOKEN_ID_CHARS + 1];
    char drop_id[ETOKEN_ID_CHARS + 1];
    char request[256];

    snprintf(keep_id, sizeof(keep_id), "%s", data_string(keep, "id"));
    snprintf(drop_id, sizeof(drop_id), "%s", data_string(drop, "id"));
    cJSON_Delete(keep);
    cJSON_Delete(drop);

    snprintf(request, sizeof(request), "{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"%s\"}}", drop_id);
    cJSON_Delete(dispatch(request));

    cJSON *response = dispatch("{\"function\":\"token_purge\",\"arguments\":{\"scope\":\"dead\"}}");
    assert_int_equal(response_error(response), 0);
    cJSON *data = cJSON_GetObjectItem(response, "data");
    char *ids = cJSON_PrintUnformatted(cJSON_GetObjectItem(data, "ids"));

    // At least the one this case revoked; earlier cases may have left dead tokens of their own.
    assert_true(cJSON_GetObjectItem(data, "removed")->valueint >= 1);
    assert_non_null(strstr(ids, drop_id));
    assert_null(strstr(ids, keep_id));
    free(ids);
    cJSON_Delete(response);

    // What the operator sees afterwards: the revoked one is gone, not marked -- that is the whole
    // difference between revoking and purging -- and the live one is untouched.
    response = dispatch("{\"function\":\"token_list\"}");
    char *printed = cJSON_PrintUnformatted(cJSON_GetObjectItem(response, "data"));
    assert_null(strstr(printed, drop_id));
    assert_non_null(strstr(printed, keep_id));
    free(printed);
    cJSON_Delete(response);
}

static void test_token_purge_all_and_default_scope(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    cJSON_Delete(mint("{\"address\":\"wazuh-1\"}"));

    // No arguments at all: the harmless scope, so a caller can never empty the store by omission.
    // Nothing here is dead (the previous case purged), so the store must come out untouched.
    int before = token_list_size();
    cJSON *response = dispatch("{\"function\":\"token_purge\"}");
    assert_int_equal(response_error(response), 0);
    assert_int_equal(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "removed")->valueint, 0);
    assert_int_equal(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "remaining")->valueint, before);
    cJSON_Delete(response);

    response = dispatch("{\"function\":\"token_purge\",\"arguments\":{\"scope\":\"all\"}}");
    assert_int_equal(response_error(response), 0);
    assert_int_equal(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "removed")->valueint, before);
    assert_int_equal(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "remaining")->valueint, 0);
    cJSON_Delete(response);
}

static void test_token_purge_unknown_scope_is_refused(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_ERROR();
    cJSON_Delete(mint("{\"address\":\"wazuh-1\"}"));

    int before = token_list_size();

    // "expired" is a scope somebody could reasonably expect: answering it as "dead" would purge more
    // than they asked for, so it is an error and the store is left alone.
    cJSON *response = dispatch("{\"function\":\"token_purge\",\"arguments\":{\"scope\":\"expired\"}}");
    // 9002: the same "the arguments do not make sense" the rest of the verbs answer with.
    assert_int_equal(response_error(response), 9002);
    cJSON_Delete(response);

    assert_int_equal(token_list_size(), before);
}

static void test_token_purge_on_worker_9015(void **state) {
    (void)state;
    EXPECT_LOG_ERROR();
    config.worker_node = TRUE;
    cJSON *response = dispatch("{\"function\":\"token_purge\",\"arguments\":{\"scope\":\"all\"}}");
    assert_int_equal(response_error(response), 9015);
    cJSON_Delete(response);
    config.worker_node = FALSE;
}

static void test_token_list_and_revoke(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_ERROR();
    cJSON *minted = mint("{\"address\":\"wazuh-1\",\"description\":\"to revoke\"}");
    char id[ETOKEN_ID_CHARS + 1];
    strncpy(id, data_string(minted, "id"), sizeof(id) - 1);
    id[sizeof(id) - 1] = '\0';
    // The secret as it would appear anywhere it leaked: base64url of the second half of `key`.
    w_etoken_t token;
    assert_int_equal(w_etoken_decode(data_string(minted, "token"), &token), ETOKEN_OK);
    char *secret_b64 = w_b64url_encode(token.secret, W_ETOKEN_SECRET_BYTES);
    w_etoken_free(&token);
    cJSON_Delete(minted);

    cJSON *response = dispatch("{\"function\":\"token_list\"}");
    assert_int_equal(response_error(response), 0);
    cJSON *list = cJSON_GetObjectItem(response, "data");
    assert_true(cJSON_IsArray(list));
    assert_true(cJSON_GetArraySize(list) >= 1);
    char *printed = cJSON_PrintUnformatted(list);
    assert_null(strstr(printed, secret_b64));
    assert_null(strstr(printed, "\"secret\""));
    assert_null(strstr(printed, "\"token\""));
    assert_non_null(strstr(printed, id));
    assert_non_null(strstr(printed, "\"revoked\":false"));
    free(printed);
    cJSON_Delete(response);

    char request[256];
    snprintf(request, sizeof(request), "{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"%s\"}}", id);
    response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    cJSON_Delete(response);

    response = dispatch("{\"function\":\"token_list\"}");
    cJSON *entry = NULL;
    int seen = 0;
    cJSON_ArrayForEach(entry, cJSON_GetObjectItem(response, "data")) {
        if (strcmp(cJSON_GetObjectItem(entry, "id")->valuestring, id) == 0) {
            assert_true(cJSON_IsTrue(cJSON_GetObjectItem(entry, "revoked")));
            seen = 1;
        }
    }
    assert_true(seen);
    cJSON_Delete(response);

    // Unknown id and an id of the wrong shape are the same 9022; a missing id is 9004.
    response = dispatch("{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"AAECAwQFBgcICQoLDA0ODw\"}}");
    assert_int_equal(response_error(response), 9022);
    cJSON_Delete(response);
    response = dispatch("{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"not-a-token-id\"}}");
    assert_int_equal(response_error(response), 9022);
    cJSON_Delete(response);
    response = dispatch("{\"function\":\"token_revoke\",\"arguments\":{}}");
    assert_int_equal(response_error(response), 9004);
    cJSON_Delete(response);
    free(secret_b64);
}

static void test_add_with_token_consumes_and_releases(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_ERROR();
    cJSON *minted = mint("{\"address\":\"wazuh-1\",\"max_uses\":1}");
    char id[ETOKEN_ID_CHARS + 1];
    strncpy(id, data_string(minted, "id"), sizeof(id) - 1);
    id[sizeof(id) - 1] = '\0';
    cJSON_Delete(minted);
    assert_int_equal(uses_on_disk(id), 0);

    char request[512];
    // The only add that reaches the keystore: OS_AddKey() validates the ip through OS_IsValidIP(),
    // wrapped here like in test_auth_add.c (the real one needs the pcre2 mocks).
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    snprintf(request, sizeof(request), "{\"function\":\"add\",\"arguments\":{\"name\":\"tok-agent\",\"ip\":\"any\",\"token_id\":\"%s\"}}", id);
    cJSON *response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    assert_string_equal(data_string(response, "name"), "tok-agent");
    cJSON_Delete(response);
    assert_int_equal(uses_on_disk(id), 1);

    // max_uses 1 reached: the next enrollment with this token is refused before the keystore is touched.
    snprintf(request, sizeof(request), "{\"function\":\"add\",\"arguments\":{\"name\":\"tok-agent-2\",\"ip\":\"any\",\"token_id\":\"%s\"}}", id);
    response = dispatch(request);
    assert_int_equal(response_error(response), 9024);
    cJSON_Delete(response);
    assert_int_equal(uses_on_disk(id), 1);
    assert_int_equal(OS_IsAllowedName(&keys, "tok-agent-2"), -1);

    // A token with room whose enrollment fails afterwards gives the use back: the duplicate name is
    // refused by local_add() with force disabled (self-contained: no wazuh-db, no regex), 9008.
    minted = mint("{\"address\":\"wazuh-1\",\"max_uses\":5}");
    char id2[ETOKEN_ID_CHARS + 1];
    strncpy(id2, data_string(minted, "id"), sizeof(id2) - 1);
    id2[sizeof(id2) - 1] = '\0';
    cJSON_Delete(minted);
    snprintf(request, sizeof(request), "{\"function\":\"add\",\"arguments\":{\"name\":\"tok-agent\",\"ip\":\"any\",\"token_id\":\"%s\"}}", id2);
    response = dispatch(request);
    assert_int_equal(response_error(response), 9008);
    cJSON_Delete(response);
    assert_int_equal(uses_on_disk(id2), 0);

    // A token id of the wrong shape never reaches the store: 9022.
    response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"tok-agent-3\",\"ip\":\"any\",\"token_id\":\"short\"}}");
    assert_int_equal(response_error(response), 9022);
    cJSON_Delete(response);
}

static void test_token_revoke_storage_failure_is_not_a_missing_token(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_ERROR();
    cJSON *minted = mint("{\"address\":\"wazuh-1\",\"description\":\"storage\"}");
    char id[ETOKEN_ID_CHARS + 1];
    char request[256];

    snprintf(id, sizeof(id), "%s", data_string(minted, "id"));
    cJSON_Delete(minted);

    // Point the store at a directory that does not exist: every write fails from here on. The
    // token is still there, so answering 9022 would send the operator looking for a token that
    // exists when what they have to do is retry (issue #39078, H04).
    etoken_store_init("etc/no-such-directory/enrollment_tokens.json");

    snprintf(request, sizeof(request), "{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"%s\"}}", id);
    cJSON *response = dispatch(request);
    assert_int_equal(response_error(response), 9029);
    cJSON_Delete(response);

    // An id that is genuinely unknown still answers 9022, even while storage is broken.
    response = dispatch("{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"AAAAAAAAAAAAAAAAAAAAAA\"}}");
    assert_int_equal(response_error(response), 9022);
    cJSON_Delete(response);

    // Storage back: the pending revocation is written and the verb answers success.
    etoken_store_init(TOKENS_FILE);
    response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    cJSON_Delete(response);
}

static void test_add_with_token_closes_the_reservation(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    cJSON *minted = mint("{\"address\":\"wazuh-1\",\"max_uses\":1}");
    char id[ETOKEN_ID_CHARS + 1];
    char request[512];

    snprintf(id, sizeof(id), "%s", data_string(minted, "id"));
    cJSON_Delete(minted);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    snprintf(request, sizeof(request),
             "{\"function\":\"add\",\"arguments\":{\"name\":\"committed-agent\",\"ip\":\"any\",\"token_id\":\"%s\"}}", id);
    cJSON *response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    cJSON_Delete(response);

    // The enrollment is over, so the use is spent for good: a purge takes the token away. While the
    // add was running the store would have kept it, which is what stops a concurrent purge from
    // deleting a token whose use is about to be given back.
    response = dispatch("{\"function\":\"token_purge\",\"arguments\":{\"scope\":\"dead\"}}");
    assert_int_equal(response_error(response), 0);

    char *ids = cJSON_PrintUnformatted(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "ids"));
    assert_non_null(strstr(ids, id));
    free(ids);
    cJSON_Delete(response);
}

static void test_add_with_revoked_or_expired_token(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_ERROR();
    cJSON *minted = mint("{\"address\":\"wazuh-1\"}");
    char id[ETOKEN_ID_CHARS + 1];
    strncpy(id, data_string(minted, "id"), sizeof(id) - 1);
    id[sizeof(id) - 1] = '\0';
    cJSON_Delete(minted);
    char request[512];
    snprintf(request, sizeof(request), "{\"function\":\"token_revoke\",\"arguments\":{\"id\":\"%s\"}}", id);
    cJSON *response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    cJSON_Delete(response);
    snprintf(request, sizeof(request), "{\"function\":\"add\",\"arguments\":{\"name\":\"rev-agent\",\"ip\":\"any\",\"token_id\":\"%s\"}}", id);
    response = dispatch(request);
    assert_int_equal(response_error(response), 9022);
    cJSON_Delete(response);

    // ttl 1: expired one second later.
    minted = mint("{\"address\":\"wazuh-1\",\"ttl\":1}");
    strncpy(id, data_string(minted, "id"), sizeof(id) - 1);
    cJSON_Delete(minted);
    sleep(2);
    snprintf(request, sizeof(request), "{\"function\":\"add\",\"arguments\":{\"name\":\"exp-agent\",\"ip\":\"any\",\"token_id\":\"%s\"}}", id);
    response = dispatch(request);
    assert_int_equal(response_error(response), 9023);
    cJSON_Delete(response);
    // Neither agent was created.
    assert_int_equal(OS_IsAllowedName(&keys, "rev-agent"), -1);
    assert_int_equal(OS_IsAllowedName(&keys, "exp-agent"), -1);
}

static void test_local_add_returns_and_queues_a_reenroll_secret(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    // The only add that reaches the keystore: OS_AddKey() validates the ip through OS_IsValidIP().
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"rs-agent\",\"ip\":\"any\"}}");
    assert_int_equal(response_error(response), 0);
    const char *secret = data_string(response, "reenroll_secret");
    // 64 lowercase hex chars (#38993), generated next to the key...
    assert_true(OS_IsValidReenrollSecret(secret));
    assert_string_not_equal(secret, data_string(response, "key"));
    // ...and queued for the writer, which is the only way it reaches global.db (never client.keys).
    // The group fixture keeps one queue for every case, so look for this add's node, not the head.
    struct keynode *node = queue_insert;
    while (node && strcmp(node->name, "rs-agent") != 0) {
        node = node->next;
    }
    assert_non_null(node);
    assert_non_null(node->reenroll_secret);
    assert_string_equal(node->reenroll_secret, secret);
    cJSON_Delete(response);
}

static void test_local_get_never_returns_the_secret(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"get-agent\",\"ip\":\"any\"}}");
    assert_int_equal(response_error(response), 0);
    char id[16];
    strncpy(id, data_string(response, "id"), sizeof(id) - 1);
    id[sizeof(id) - 1] = '\0';
    cJSON_Delete(response);

    // `get` serves manage_agents and the API: the key, yes; the agent's re-enrollment secret, never.
    char request[128];
    snprintf(request, sizeof(request), "{\"function\":\"get\",\"arguments\":{\"id\":\"%s\"}}", id);
    response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    assert_string_equal(data_string(response, "name"), "get-agent");
    assert_non_null(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "key"));
    assert_null(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "reenroll_secret"));
    cJSON_Delete(response);
}

static void test_add_with_token_on_worker_forwards_it(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_INFO();
    EXPECT_LOG_ERROR();
    config.worker_node = TRUE;
    expect_string(__wrap_w_request_agent_add_clustered, name, "wk-agent");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_string(__wrap_w_request_agent_add_clustered, token_id, "AAECAwQFBgcICQoLDA0ODw");
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_kid, NULL);
    expect_value(__wrap_w_request_agent_add_clustered, reenroll_bearer, NULL);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "007");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    will_return(__wrap_w_request_agent_add_clustered, "");
    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"wk-agent\",\"ip\":\"any\",\"token_id\":\"AAECAwQFBgcICQoLDA0ODw\"}}");
    assert_int_equal(response_error(response), 0);
    assert_string_equal(data_string(response, "id"), "007");
    cJSON_Delete(response);
    // The shape check runs on the worker too: garbage never travels to the master.
    response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"wk-agent\",\"ip\":\"any\",\"token_id\":\"nope\"}}");
    assert_int_equal(response_error(response), 9022);
    cJSON_Delete(response);
    config.worker_node = FALSE;
}

// ---------------------------------------------------------------- re-enrollment (#38993)

#define REENROLL_BEARER "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.claims.signature"
#define REENROLL_SECRET "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// One first enrollment through the socket; the add reaches the keystore, so OS_AddKey()'s OS_IsValidIP() is
// expected once. Returns the id (and the key, when asked) the answer carried.
static void add_agent(const char *name, char *id_out, size_t id_size, char *key_out, size_t key_size) {
    char request[256];
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    snprintf(request, sizeof(request), "{\"function\":\"add\",\"arguments\":{\"name\":\"%s\",\"ip\":\"any\"}}", name);
    cJSON *response = dispatch(request);
    assert_int_equal(response_error(response), 0);
    strncpy(id_out, data_string(response, "id"), id_size - 1);
    id_out[id_size - 1] = '\0';
    if (key_out) {
        strncpy(key_out, data_string(response, "key"), key_size - 1);
        key_out[key_size - 1] = '\0';
    }
    cJSON_Delete(response);
}

// The get-agent-info answer wazuh-db gives for one row: an array holding the row (the caller frees it).
static cJSON *agent_row(int id, const char *reenroll_secret) {
    cJSON *rows = cJSON_CreateArray();
    cJSON *row = cJSON_CreateObject();
    cJSON_AddNumberToObject(row, "id", id);
    cJSON_AddStringToObject(row, "name", "whatever");
    if (reenroll_secret) {
        cJSON_AddStringToObject(row, "reenroll_secret", reenroll_secret);
    }
    cJSON_AddItemToArray(rows, row);
    return rows;
}

static cJSON *reenroll(const char *kid, const char *name) {
    char request[1024];
    snprintf(request, sizeof(request),
             "{\"function\":\"add\",\"arguments\":{\"name\":\"%s\",\"ip\":\"any\",\"reenroll\":{\"kid\":\"%s\",\"bearer\":\"" REENROLL_BEARER "\"}}}",
             name, kid);
    return dispatch(request);
}

static void expect_verify(const char *kid, const char *secret, int verdict) {
    expect_string(__wrap_w_reenroll_verify, bearer, REENROLL_BEARER);
    expect_string(__wrap_w_reenroll_verify, agent_id, kid);
    expect_string(__wrap_w_reenroll_verify, secret_hex, secret);
    will_return(__wrap_w_reenroll_verify, verdict);
}

// The LAST node of `queue` for `id`: the group fixture keeps one queue for every case, so an agent's first
// enrollment (an insert node) precedes its rotation in the same queue.
static struct keynode *find_node(struct keynode *queue, const char *id) {
    struct keynode *found = NULL;
    for (; queue; queue = queue->next) {
        if (strcmp(queue->id, id) == 0) {
            found = queue;
        }
    }
    return found;
}

static void test_reenroll_unknown_agent_9026(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    // No row at all: nothing to verify against, and the bearer is never looked at.
    expect_value(__wrap_wdb_get_agent_info, id, 999);
    will_return(__wrap_wdb_get_agent_info, NULL);
    cJSON *response = reenroll("999", "ghost-agent");
    assert_int_equal(response_error(response), 9026);
    cJSON_Delete(response);
}

static void test_reenroll_without_secret_9026(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    // A row without reenroll_secret (a worker's mirror of client.keys, an agent enrolled over 1515): same
    // answer as no row -- the caller cannot tell the two apart, by design.
    expect_value(__wrap_wdb_get_agent_info, id, 42);
    will_return(__wrap_wdb_get_agent_info, agent_row(42, NULL));
    cJSON *response = reenroll("042", "legacy-agent");
    assert_int_equal(response_error(response), 9026);
    cJSON_Delete(response);
}

static void test_reenroll_invalid_bearer_9027(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    expect_value(__wrap_wdb_get_agent_info, id, 7);
    will_return(__wrap_wdb_get_agent_info, agent_row(7, REENROLL_SECRET));
    expect_verify("007", REENROLL_SECRET, W_REENROLL_INVALID);
    cJSON *response = reenroll("007", "some-agent");
    assert_int_equal(response_error(response), 9027);
    cJSON_Delete(response);
}

static void test_reenroll_stale_9028(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    expect_value(__wrap_wdb_get_agent_info, id, 7);
    will_return(__wrap_wdb_get_agent_info, agent_row(7, REENROLL_SECRET));
    expect_verify("007", REENROLL_SECRET, W_REENROLL_STALE);
    cJSON *response = reenroll("007", "some-agent");
    assert_int_equal(response_error(response), 9028);
    cJSON_Delete(response);
}

static void test_reenroll_rotates_key_and_secret_keeping_the_id(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    char id[16];
    char old_key[128];
    add_agent("rot-agent", id, sizeof(id), old_key, sizeof(old_key));
    const unsigned int keysize_before = keys.keysize;

    // The row wazuh-db holds for it, its secret verified for real by the bridge (wrapped: verdict OK), then
    // OS_AddNewAgent() re-adds the entry -> OS_AddKey() -> OS_IsValidIP() once more.
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_OK);
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *response = reenroll(id, "rot-agent");
    assert_int_equal(response_error(response), 0);
    // Same id, a fresh key, a fresh secret -- the five fields of a first enrollment.
    assert_string_equal(data_string(response, "id"), id);
    assert_string_equal(data_string(response, "name"), "rot-agent");
    const char *new_key = data_string(response, "key");
    const char *new_secret = data_string(response, "reenroll_secret");
    assert_true(OS_IsValidAgentKey(new_key));
    assert_string_not_equal(new_key, old_key);
    assert_true(OS_IsValidReenrollSecret(new_secret));
    assert_string_not_equal(new_secret, REENROLL_SECRET);

    // The keystore: the same id, now with the new key; nothing added, nothing removed.
    int index = OS_IsAllowedID(&keys, id);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->raw_key, new_key);
    assert_string_equal(keys.keyentries[index]->name, "rot-agent");
    assert_int_equal(keys.keysize, keysize_before);
    assert_int_equal(OS_IsAllowedName(&keys, "rot-agent"), index);

    // The writer's queues: one rotation node (UPDATE, groups untouched) and no removal -- no purge.
    struct keynode *node = find_node(queue_insert, id);
    assert_non_null(node);
    assert_int_equal(node->rotate, 1);
    assert_null(node->group);
    assert_string_equal(node->raw_key, new_key);
    assert_string_equal(node->reenroll_secret, new_secret);
    assert_null(find_node(queue_remove, id));
    cJSON_Delete(response);
}

/* --- The credential is written down before it is handed out (issue #39078, H03) -------------- */

static void test_an_accepted_enrollment_is_journaled_with_its_credential(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"journaled-agent\",\"ip\":\"any\"}}");
    assert_int_equal(response_error(response), 0);

    // The same key and the same secret the caller was just given: what the journal holds is what
    // the database owes, and it is the credential itself -- a digest would restore nothing.
    size_t count = 0;
    identity_journal_entry_t *entries = identity_journal_snapshot(0, 0, &count);
    identity_journal_entry_t *mine = NULL;
    for (size_t i = 0; i < count; i++) {
        if (!strcmp(entries[i].id, data_string(response, "id"))) {
            mine = &entries[i];
        }
    }
    assert_non_null(mine);
    assert_string_equal(mine->key, data_string(response, "key"));
    assert_string_equal(mine->secret, data_string(response, "reenroll_secret"));
    assert_false(mine->rotate);
    identity_journal_free(entries, count);
    cJSON_Delete(response);
}

static void test_an_enrollment_that_cannot_be_journaled_is_refused(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_ERROR();
    const unsigned int keysize_before = keys.keysize;
    identity_journal_init("queue/no-such-directory/pending-identities");

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"unrecorded-agent\",\"ip\":\"any\"}}");
    // No credential is handed out: an agent whose secret nothing durable holds could never
    // re-enroll, and nobody would ever know it had one.
    assert_int_equal(response_error(response), 9031);
    assert_null(cJSON_GetObjectItem(cJSON_GetObjectItem(response, "data"), "key"));
    // And the addition is undone rather than left half-done.
    assert_int_equal(keys.keysize, keysize_before);
    assert_int_equal(OS_IsAllowedName(&keys, "unrecorded-agent"), -1);
    cJSON_Delete(response);

    identity_journal_init(IDENTITY_JOURNAL_PATH);
}

static void test_a_full_journal_refuses_before_a_replacement_destroys_the_previous_agent(void **state) {
    (void)state;
    // The successful add logs minfo, the refusal mwarn, and local_dispatch mdebug2 -- and no
    // merror, because the refusal returns before the dispatcher's failure path. An undeclared
    // severity aborts inside the store mutex and HANGS the run; a declared one that never fires
    // fails the case (see the note above).
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_WARN();

    // The agent the enrollment below would replace: same name, and <force> deletes it. The manager
    // default is what decides here, so the request needs no force block of its own.
    const authd_force_options_t saved_force = config.force_options;
    config.force_options.enabled = true;
    config.force_options.key_mismatch = false;
    config.force_options.disconnected_time_enabled = false;
    config.force_options.after_registration_time = 0;

    char victim_id[16];
    add_agent("victim", victim_id, sizeof(victim_id), NULL, 0);

    // A journal with no room left. The cases before this one left their own transitions in it,
    // so what is filled is the room that remains.
    char filler[16];
    for (size_t room = IDENTITY_JOURNAL_MAX_ENTRIES - identity_journal_pending(); room > 0; room--) {
        snprintf(filler, sizeof(filler), "%zu", room);
        assert_true(identity_journal_append(filler, "filler", "any", REENROLL_SECRET, REENROLL_SECRET, false, NULL));
    }
    assert_true(identity_journal_full());

    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"victim\",\"ip\":\"any\"}}");

    // Refused, and refused EARLY -- no OS_IsValidIP is even consumed, because the keystore is never
    // reached: w_auth_replace_agent() deletes the previous agent while it validates, so a refusal
    // discovered after that point would answer 9031 with that agent already gone and queued for the
    // indexer purge.
    assert_int_equal(response_error(response), 9031);
    cJSON_Delete(response);

    assert_true(OS_IsAllowedID(&keys, victim_id) >= 0);
    assert_true(OS_IsAllowedName(&keys, "victim") >= 0);
    assert_null(find_node(queue_remove, victim_id));

    identity_journal_init(IDENTITY_JOURNAL_PATH);
    config.force_options = saved_force;
}

static void test_a_rotation_that_cannot_be_journaled_is_refused_and_frees_the_reservation(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_ERROR();
    char id[16];
    char old_key[128];
    add_agent("unrecorded-rot", id, sizeof(id), old_key, sizeof(old_key));

    identity_journal_init("queue/no-such-directory/pending-identities");
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_OK);

    cJSON *response = reenroll(id, "unrecorded-rot");
    assert_int_equal(response_error(response), 9031);
    // The keystore is untouched: the entry still holds the key the agent already has.
    int index = OS_IsAllowedID(&keys, id);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->raw_key, old_key);
    cJSON_Delete(response);

    // And the reservation was released, so the very next attempt goes through -- 9031 is a
    // "come back", not a state that locks the agent out.
    identity_journal_init(IDENTITY_JOURNAL_PATH);
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_OK);
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    response = reenroll(id, "unrecorded-rot");
    assert_int_equal(response_error(response), 0);
    assert_string_not_equal(data_string(response, "key"), old_key);
    cJSON_Delete(response);
}

static void test_reenroll_twice_with_the_same_bearer_rotates_once(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    char id[16];
    char old_key[128];
    add_agent("twice-agent", id, sizeof(id), old_key, sizeof(old_key));

    // First rotation: accepted, queued, and NOT yet persisted -- the writer does not run in these
    // tests, which is exactly the window the finding is about (issue #39078, H02).
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_OK);
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *first = reenroll(id, "twice-agent");
    assert_int_equal(response_error(first), 0);
    const char *first_key = data_string(first, "key");
    assert_string_not_equal(first_key, old_key);

    // The same bearer again. The row still says the old secret -- that is the point -- so before
    // this the request verified again and handed out a SECOND credential for one agent. No
    // wdb_get_agent_info() is expected now: the reservation refuses it before the database is asked.
    cJSON *second = reenroll(id, "twice-agent");
    assert_int_equal(response_error(second), 9030);

    // One key, and it is the first answer's: the second caller got nothing to remember.
    int index = OS_IsAllowedID(&keys, id);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->raw_key, first_key);

    // One rotation node queued, not two.
    struct keynode *node = find_node(queue_insert, id);
    assert_non_null(node);
    assert_string_equal(node->raw_key, first_key);
    assert_null(find_node(node->next, id));

    cJSON_Delete(first);
    cJSON_Delete(second);
}

static void test_reenroll_reservation_is_released_when_the_request_is_rejected(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    char id[16];
    char old_key[128];
    add_agent("released-agent", id, sizeof(id), old_key, sizeof(old_key));

    // A bearer that does not verify: nothing was handed out, so the agent must be free to try again
    // at once -- a reservation left behind here would lock it out until authd restarts.
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_INVALID);

    cJSON *rejected = reenroll(id, "released-agent");
    assert_int_equal(response_error(rejected), 9027);
    cJSON_Delete(rejected);

    // And now a good one goes through.
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_OK);
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *accepted = reenroll(id, "released-agent");
    assert_int_equal(response_error(accepted), 0);
    cJSON_Delete(accepted);
}

static void test_reenroll_after_the_writer_persists_needs_the_new_secret(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    char id[16];
    char old_key[128];
    add_agent("persisted-agent", id, sizeof(id), old_key, sizeof(old_key));

    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_OK);
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    cJSON *first = reenroll(id, "persisted-agent");
    assert_int_equal(response_error(first), 0);
    cJSON_Delete(first);

    // What the writer does when the credentials reach the database: the reservation is released and
    // the generation moves on.
    w_reenroll_complete(id);

    // The old bearer now meets the NEW secret in the row, so it is a plain signature failure (9027)
    // -- not "already in progress": there is nothing in flight any more.
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id), REENROLL_SECRET));
    expect_verify(id, REENROLL_SECRET, W_REENROLL_INVALID);

    cJSON *second = reenroll(id, "persisted-agent");
    assert_int_equal(response_error(second), 9027);
    cJSON_Delete(second);
}

static void test_reenroll_duplicate_name_of_another_agent_9008(void **state) {
    (void)state;
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG1();
    EXPECT_LOG_DEBUG2();
    char id_a[16];
    char key_a[128];
    char id_b[16];
    add_agent("dup-a", id_a, sizeof(id_a), key_a, sizeof(key_a));
    add_agent("dup-b", id_b, sizeof(id_b), NULL, 0);

    // A valid credential for dup-a asking to be called dup-b: another agent's name, refused like a first
    // enrollment would be; dup-a keeps its key.
    expect_value(__wrap_wdb_get_agent_info, id, atoi(id_a));
    will_return(__wrap_wdb_get_agent_info, agent_row(atoi(id_a), REENROLL_SECRET));
    expect_verify(id_a, REENROLL_SECRET, W_REENROLL_OK);
    cJSON *response = reenroll(id_a, "dup-b");
    assert_int_equal(response_error(response), 9008);
    cJSON_Delete(response);
    int index = OS_IsAllowedID(&keys, id_a);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->raw_key, key_a);
    assert_string_equal(keys.keyentries[index]->name, "dup-a");
}

static void test_reenroll_malformed_or_with_token_id_9027(void **state) {
    (void)state;
    EXPECT_LOG_ERROR();
    static const char *const requests[] = {
        // not an object
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":\"001\"}}",
        // no kid
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":{\"bearer\":\"x.y.z\"}}}",
        // kid that is not an agent id
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":{\"kid\":\"abc\",\"bearer\":\"x.y.z\"}}}",
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":{\"kid\":\"\",\"bearer\":\"x.y.z\"}}}",
        // no bearer / empty bearer / bearer of the wrong type
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":{\"kid\":\"001\"}}}",
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":{\"kid\":\"001\",\"bearer\":\"\"}}}",
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"reenroll\":{\"kid\":\"001\",\"bearer\":5}}}",
        // combined with another credential or a caller-chosen identity
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"token_id\":\"AAECAwQFBgcICQoLDA0ODw\",\"reenroll\":{\"kid\":\"001\",\"bearer\":\"x.y.z\"}}}",
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"id\":\"001\",\"reenroll\":{\"kid\":\"001\",\"bearer\":\"x.y.z\"}}}",
        "{\"function\":\"add\",\"arguments\":{\"name\":\"a\",\"ip\":\"any\",\"key\":\"" REENROLL_SECRET "\",\"reenroll\":{\"kid\":\"001\",\"bearer\":\"x.y.z\"}}}",
    };
    // None of these reaches wazuh-db or the bridge: no expectations on either wrap.
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
        cJSON *response = dispatch(requests[i]);
        assert_int_equal(response_error(response), 9027);
        cJSON_Delete(response);
    }
    // An explicit null is "not supplied", the classic add.
    EXPECT_LOG_INFO();
    EXPECT_LOG_DEBUG2();
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    cJSON *response = dispatch("{\"function\":\"add\",\"arguments\":{\"name\":\"null-reenroll\",\"ip\":\"any\",\"reenroll\":null}}");
    assert_int_equal(response_error(response), 0);
    cJSON_Delete(response);
}

static void test_reenroll_on_worker_forwards_kid_and_bearer(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_INFO();
    config.worker_node = TRUE;
    // The worker verifies nothing (it has no secret to verify against): kid and bearer travel verbatim, and
    // the master's rotated credentials come back as they are.
    expect_string(__wrap_w_request_agent_add_clustered, name, "wk-reenroll");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_value(__wrap_w_request_agent_add_clustered, token_id, NULL);
    expect_string(__wrap_w_request_agent_add_clustered, reenroll_kid, "001");
    expect_string(__wrap_w_request_agent_add_clustered, reenroll_bearer, REENROLL_BEARER);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "001");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    will_return(__wrap_w_request_agent_add_clustered, REENROLL_SECRET);
    cJSON *response = reenroll("001", "wk-reenroll");
    assert_int_equal(response_error(response), 0);
    assert_string_equal(data_string(response, "id"), "001");
    assert_string_equal(data_string(response, "reenroll_secret"), REENROLL_SECRET);
    cJSON_Delete(response);
    config.worker_node = FALSE;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_local_add_clustered_success),
        cmocka_unit_test(test_local_add_clustered_business_rejection_preserves_master_code),
        cmocka_unit_test(test_local_add_clustered_transport_failure_maps_to_9016),
        cmocka_unit_test(test_local_add_rejects_a_malformed_explicit_key),
        cmocka_unit_test(test_local_add_rejects_an_out_of_range_or_reserved_id),
        cmocka_unit_test(test_storable_agent_name_accepts_ordinary_names),
        cmocka_unit_test(test_storable_agent_name_accepts_names_os_isvalidname_rejects),
        cmocka_unit_test(test_storable_agent_name_rejects_whitespace_and_control_bytes),
        cmocka_unit_test(test_storable_agent_name_rejects_removed_entry_markers),
        cmocka_unit_test(test_storable_agent_name_rejects_empty_and_overlong),
        cmocka_unit_test(test_optional_string_arg_absent_or_null_means_not_supplied),
        cmocka_unit_test(test_optional_string_arg_returns_string_values),
        cmocka_unit_test(test_optional_string_arg_rejects_non_string_types),
    };

    const struct CMUnitTest token_tests[] = {
        cmocka_unit_test(test_token_create_ok),
        cmocka_unit_test(test_token_create_refusals_9025),
        cmocka_unit_test(test_token_create_ip_warns_and_overrides),
        cmocka_unit_test(test_token_create_embed_ca_no_credential),
        cmocka_unit_test(test_token_create_embed_ca_never_carries_a_private_key),
        cmocka_unit_test(test_token_create_embed_ca_accepts_a_bundle_signed_by_its_second_certificate),
        cmocka_unit_test(test_token_create_bad_arguments),
        cmocka_unit_test(test_token_verbs_on_worker_9015),
        cmocka_unit_test(test_token_list_and_revoke),
        cmocka_unit_test(test_token_purge_removes_and_reports),
        cmocka_unit_test(test_token_purge_all_and_default_scope),
        cmocka_unit_test(test_token_purge_unknown_scope_is_refused),
        cmocka_unit_test(test_token_purge_on_worker_9015),
        cmocka_unit_test(test_add_with_token_consumes_and_releases),
        cmocka_unit_test(test_token_revoke_storage_failure_is_not_a_missing_token),
        cmocka_unit_test(test_add_with_token_closes_the_reservation),
        cmocka_unit_test(test_add_with_revoked_or_expired_token),
        cmocka_unit_test(test_add_with_token_on_worker_forwards_it),
        cmocka_unit_test(test_local_add_returns_and_queues_a_reenroll_secret),
        cmocka_unit_test(test_local_get_never_returns_the_secret),
        cmocka_unit_test(test_reenroll_unknown_agent_9026),
        cmocka_unit_test(test_reenroll_without_secret_9026),
        cmocka_unit_test(test_reenroll_invalid_bearer_9027),
        cmocka_unit_test(test_reenroll_stale_9028),
        cmocka_unit_test(test_reenroll_rotates_key_and_secret_keeping_the_id),
        cmocka_unit_test(test_an_accepted_enrollment_is_journaled_with_its_credential),
        cmocka_unit_test(test_an_enrollment_that_cannot_be_journaled_is_refused),
        cmocka_unit_test(test_a_rotation_that_cannot_be_journaled_is_refused_and_frees_the_reservation),
        cmocka_unit_test(test_a_full_journal_refuses_before_a_replacement_destroys_the_previous_agent),
        cmocka_unit_test(test_reenroll_twice_with_the_same_bearer_rotates_once),
        cmocka_unit_test(test_reenroll_reservation_is_released_when_the_request_is_rejected),
        cmocka_unit_test(test_reenroll_after_the_writer_persists_needs_the_new_secret),
        cmocka_unit_test(test_reenroll_duplicate_name_of_another_agent_9008),
        cmocka_unit_test(test_reenroll_malformed_or_with_token_id_9027),
        cmocka_unit_test(test_reenroll_on_worker_forwards_kid_and_bearer),
    };
    int failed = cmocka_run_group_tests(tests, NULL, NULL);
    failed += cmocka_run_group_tests(token_tests, setup_token_env, teardown_token_env);
    return failed;
}

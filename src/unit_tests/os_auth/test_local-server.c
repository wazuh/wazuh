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
                                         authd_force_options_t *force_options,
                                         const char *agent_id,
                                         const char *token_id,
                                         int *master_error_code) {
    check_expected(name);
    check_expected(ip);
    // NULL when the enrollment carried no token; the id text otherwise (#38993).
    check_expected(token_id);

    // Mirrors local_add_clustered()'s contract: no caller-supplied id/key/force is ever
    // forwarded on a worker.
    assert_null(force_options);
    assert_null(agent_id);

    int result = mock_type(int);

    if (result == 0) {
        const char *mock_id = mock_ptr_type(const char *);
        const char *mock_key = mock_ptr_type(const char *);
        os_strdup(mock_id, *id);
        os_strdup(mock_key, *key);
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
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "003");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");

    response = local_add_clustered("agent1", "any", NULL, NULL, NULL);
    assert_non_null(response);

    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    data = cJSON_GetObjectItem(response, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "id")->valuestring, "003");
    assert_string_equal(cJSON_GetObjectItem(data, "name")->valuestring, "agent1");
    assert_string_equal(cJSON_GetObjectItem(data, "ip")->valuestring, "any");
    assert_string_equal(cJSON_GetObjectItem(data, "key")->valuestring,
                        "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");

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
    will_return(__wrap_w_request_agent_add_clustered, -1);
    will_return(__wrap_w_request_agent_add_clustered, 9008);
    will_return(__wrap_w_request_agent_add_clustered, "ERROR: Duplicate name");

    response = local_add_clustered("agent1", "any", NULL, NULL, NULL);
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
    will_return(__wrap_w_request_agent_add_clustered, -2);
    will_return(__wrap_w_request_agent_add_clustered, 0); // master_error_code left untouched
    will_return(__wrap_w_request_agent_add_clustered, "ERROR: Cannot communicate with master");

    response = local_add_clustered("agent1", "any", NULL, NULL, NULL);
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
    assert_string_equal(token.ca_pem, CA_PEM);
    w_etoken_free(&token);
    cJSON_Delete(response);
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

static void test_add_with_token_on_worker_forwards_it(void **state) {
    (void)state;
    EXPECT_LOG_DEBUG2();
    EXPECT_LOG_INFO();
    EXPECT_LOG_ERROR();
    config.worker_node = TRUE;
    expect_string(__wrap_w_request_agent_add_clustered, name, "wk-agent");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    expect_string(__wrap_w_request_agent_add_clustered, token_id, "AAECAwQFBgcICQoLDA0ODw");
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "007");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
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
        cmocka_unit_test(test_token_create_bad_arguments),
        cmocka_unit_test(test_token_verbs_on_worker_9015),
        cmocka_unit_test(test_token_list_and_revoke),
        cmocka_unit_test(test_add_with_token_consumes_and_releases),
        cmocka_unit_test(test_add_with_revoked_or_expired_token),
        cmocka_unit_test(test_add_with_token_on_worker_forwards_it),
    };
    int failed = cmocka_run_group_tests(tests, NULL, NULL);
    failed += cmocka_run_group_tests(token_tests, setup_token_env, teardown_token_env);
    return failed;
}

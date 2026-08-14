/*
 * Copyright (C) 2015, Wazuh Inc.
 * August 12, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>

#include "http_op.h"

/* These tests deliberately point at a socket path that does NOT exist. That makes them hermetic --
 * no server, no fixture -- while still answering the only question that matters here: did the call
 * reach libcurl at all? A request that was attempted comes back with a non-zero `curl_code`
 * (CURLE_COULDNT_CONNECT); a request rejected by argument validation returns non-zero WITHOUT
 * touching `out`, leaving `curl_code` at 0, which is CURLE_OK. Those two are indistinguishable to a
 * caller that only looks at `curl_code`, and that is exactly how a body-less POST silently never
 * left the process. */
#define MISSING_SOCKET "/tmp/wazuh-test-http-op-no-such.sock"

static uhttp_client_t* new_test_client(void)
{
    uhttp_options_t opt = {.unix_socket_path = MISSING_SOCKET,
                           .url = "http://localhost/agents/delete",
                           .timeout_ms = 1000,
                           .connect_timeout_ms = 500,
                           .keepalive = true};
    return uhttp_client_new(&opt);
}

/* ------------------------------------- uhttp_post ------------------------------------- */

/**
 * A POST with NO body must be SENT. Regression test: the argument guard used to reject `len == 0`
 * before curl_easy_perform(), so every caller whose request carries its input in headers (the
 * inventory sync server's /agents/delete takes its target from X-Wazuh-Agent-Id and ignores the
 * body) failed instantly, reporting curl code 0 and no HTTP status while nothing was ever sent.
 */
void test_uhttp_post_sends_an_empty_body(void** state)
{
    (void)state;

    uhttp_client_t* client = new_test_client();
    assert_non_null(client);

    uhttp_result_t result = {0};
    const int rc = uhttp_post(client, NULL, 0, &result);

    /* The socket does not exist, so the transfer fails -- the point is that it was ATTEMPTED. */
    assert_int_not_equal(0, rc);
    assert_int_not_equal(0, result.curl_code);

    uhttp_client_free(client);
}

/** Same, with a non-NULL pointer and a zero length: also a legitimate empty body. */
void test_uhttp_post_sends_a_zero_length_buffer(void** state)
{
    (void)state;

    uhttp_client_t* client = new_test_client();
    assert_non_null(client);

    uhttp_result_t result = {0};
    const int rc = uhttp_post(client, "", 0, &result);

    assert_int_not_equal(0, rc);
    assert_int_not_equal(0, result.curl_code);

    uhttp_client_free(client);
}

/** The one combination that IS contradictory stays refused, and refused without any I/O. */
void test_uhttp_post_refuses_a_null_buffer_with_a_positive_length(void** state)
{
    (void)state;

    uhttp_client_t* client = new_test_client();
    assert_non_null(client);

    uhttp_result_t result = {0};
    assert_int_equal(-1, uhttp_post(client, NULL, 8, &result));
    assert_int_equal(0, result.curl_code);  /* untouched: nothing was attempted */
    assert_int_equal(0, result.http_status);

    uhttp_client_free(client);
}

/** A NULL client is refused rather than dereferenced. */
void test_uhttp_post_refuses_a_null_client(void** state)
{
    (void)state;

    uhttp_result_t result = {0};
    assert_int_equal(-1, uhttp_post(NULL, "x", 1, &result));
}

/* -------------------------------- header list handling -------------------------------- */

/**
 * Resetting the headers must restore the client's own defaults, so a caller that swaps one
 * per-request header keeps the Content-Type, the `Expect:` suppression and the keep-alive it asked
 * for. Clearing instead of resetting dropped all three for the life of the client.
 */
void test_uhttp_client_reset_headers_succeeds_repeatedly(void** state)
{
    (void)state;

    uhttp_client_t* client = new_test_client();
    assert_non_null(client);

    for (int i = 0; i < 3; i++)
    {
        assert_int_equal(0, uhttp_client_reset_headers(client));
        assert_int_equal(0, uhttp_client_add_header(client, "X-Wazuh-Agent-Id: 007"));
    }

    /* Still usable afterwards: the reset leaves a valid list installed on the easy handle. */
    uhttp_result_t result = {0};
    assert_int_not_equal(0, uhttp_post(client, NULL, 0, &result));
    assert_int_not_equal(0, result.curl_code);

    uhttp_client_free(client);
}

/** A NULL client is refused rather than dereferenced. */
void test_uhttp_client_reset_headers_refuses_a_null_client(void** state)
{
    (void)state;

    assert_int_equal(-1, uhttp_client_reset_headers(NULL));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_uhttp_post_sends_an_empty_body),
        cmocka_unit_test(test_uhttp_post_sends_a_zero_length_buffer),
        cmocka_unit_test(test_uhttp_post_refuses_a_null_buffer_with_a_positive_length),
        cmocka_unit_test(test_uhttp_post_refuses_a_null_client),
        cmocka_unit_test(test_uhttp_client_reset_headers_succeeds_repeatedly),
        cmocka_unit_test(test_uhttp_client_reset_headers_refuses_a_null_client),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

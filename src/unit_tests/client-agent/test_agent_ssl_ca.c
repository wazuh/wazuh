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
#include <string.h>
#include <stdlib.h>

#include "agentd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/os_utils_wrappers.h"

/* w_agent_validate_ssl_ca() decides whether the agent may start with the
 * <ssl><certificate_authorities> it was given. Two behaviours matter and they
 * differ only by <verification_mode>: a verifying mode must refuse to start on a
 * CA it cannot read, while 'none' must still say something about it, because that
 * is the state a shipped config sits in until someone enables verification. */

static agent make_config(int verification_mode, char *ca)
{
    agent cfg = {0};

    cfg.ssl.verification_mode = verification_mode;
    cfg.ssl.certificate_authorities = ca;

    return cfg;
}

static void expect_ca_readable(const char *path, int readable)
{
    expect_string(__wrap_w_is_file, file, path);
    will_return(__wrap_w_is_file, readable);
}

/* --- verification_mode none: never fatal, but never silent about a bad path --- */

static void test_none_without_ca_starts_quietly(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_NONE, NULL);

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

static void test_none_with_readable_ca_starts_quietly(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_NONE, "etc/certs/root-ca.pem");

    expect_ca_readable("etc/certs/root-ca.pem", 1);

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

/* The case the shipped template used to create: a CA path that parses cleanly,
 * is never read, and so goes unnoticed until verification is turned on. */
static void test_none_with_unreadable_ca_warns_and_starts(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_NONE, "PATH");

    expect_ca_readable("PATH", 0);
    expect_string(__wrap__mwarn, formatted_msg,
                  "(4119): <ssl><certificate_authorities> is not a readable file: 'PATH'. "
                  "It is unused while <verification_mode> is 'none'; enabling verification "
                  "would stop the agent from starting.");

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

/* --- verifying modes: an unusable CA must stop the start, not be worked around --- */

static void test_full_with_readable_ca_starts(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_FULL, "etc/certs/root-ca.pem");

    expect_ca_readable("etc/certs/root-ca.pem", 1);

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

static void test_full_with_unreadable_ca_fails(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_FULL, "PATH");

    expect_ca_readable("PATH", 0);
    expect_string(__wrap__merror, formatted_msg,
                  "(4118): <ssl><verification_mode> is not 'none' but <certificate_authorities> "
                  "is missing or unreadable: 'PATH'.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
}

/* No CA at all under a verifying mode: reported as the empty path rather than
 * dereferenced, and still fatal. */
static void test_full_without_ca_fails(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_FULL, NULL);

    expect_string(__wrap__merror, formatted_msg,
                  "(4118): <ssl><verification_mode> is not 'none' but <certificate_authorities> "
                  "is missing or unreadable: ''.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
}

static void test_certificate_with_unreadable_ca_fails(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_CERT, "PATH");

    expect_ca_readable("PATH", 0);
    expect_string(__wrap__merror, formatted_msg,
                  "(4118): <ssl><verification_mode> is not 'none' but <certificate_authorities> "
                  "is missing or unreadable: 'PATH'.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_none_without_ca_starts_quietly),
        cmocka_unit_test(test_none_with_readable_ca_starts_quietly),
        cmocka_unit_test(test_none_with_unreadable_ca_warns_and_starts),
        cmocka_unit_test(test_full_with_readable_ca_starts),
        cmocka_unit_test(test_full_with_unreadable_ca_fails),
        cmocka_unit_test(test_full_without_ca_fails),
        cmocka_unit_test(test_certificate_with_unreadable_ca_fails),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

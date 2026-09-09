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
#include "../wrappers/wazuh/shared/os_cert_bundle_wrappers.h"

/* Two functions, one subject: what the agent decides to do about TLS.
 *
 * w_agent_resolve_ssl_posture() settles the mode from <ssl> plus whether a trust anchor is
 * on disk, and defaults <certificate_authorities> to that anchor (#39025).
 * w_agent_validate_ssl_ca() then decides whether the agent may start with what came out.
 * They share one wrapped w_is_file(), so a test that drives both queues two expectations --
 * and on the rows where the anchor was injected, both carry the same path.
 *
 * The resolver probes the anchor eagerly, exactly once per call, whatever the mode. So every
 * resolver test queues exactly one expect_anchor(), including the rows that discard it. */

static agent make_config(int verification_mode, char *ca)
{
    agent cfg = {0};

    cfg.ssl.verification_mode = verification_mode;
    cfg.ssl.certificate_authorities = ca;

    return cfg;
}

/* The resolver writes cfg.ssl.certificate_authorities, so its tests cannot hand it a string
 * literal the way the validator's can. */
static agent make_config_heap(int verification_mode, const char *ca)
{
    agent cfg = {0};

    cfg.ssl.verification_mode = verification_mode;
    if (ca != NULL) {
        os_strdup(ca, cfg.ssl.certificate_authorities);
    }

    return cfg;
}

static void free_config(agent *cfg)
{
    os_free(cfg->ssl.certificate_authorities);
}

static void expect_ca_readable(const char *path, int readable)
{
    expect_string(__wrap_w_is_file, file, path);
    will_return(__wrap_w_is_file, readable);
}

/* Same queue as expect_ca_readable(), named apart so a call site says which probe it is. */
static void expect_anchor(int present)
{
    expect_string(__wrap_w_is_file, file, AGENT_ANCHOR_CA);
    will_return(__wrap_w_is_file, present);
}

/* Literal, like the expectations around it: expect_string() keeps the pointer it is given
 * rather than a copy, so a formatted buffer has to outlive the call and a local one does not. */
static void expect_none_ignores_anchor(void)
{
    expect_string(__wrap__mwarn, formatted_msg,
                  "(4122): <ssl><verification_mode> is 'none' and the trust anchor '" AGENT_ANCHOR_CA
                  "' is present: TLS verification stays disabled, as configured, and the anchor is "
                  "not used. Remove <verification_mode>none</verification_mode> to verify against it.");
}

static void expect_inferred_certificate(void)
{
    expect_string(__wrap__mwarn, formatted_msg,
                  "The '<ssl><certificate_authorities>' option is configured but "
                  "'<verification_mode>' is not; defaulting '<verification_mode>' to 'certificate'.");
}

/* --- verification_mode none: never fatal, but never silent about a bad path --- */

static void test_none_without_ca_starts_quietly(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_NONE, NULL);

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

/* Queues no expectation on purpose: under 'none' the path is inert, so the validator must not
 * probe it. cmocka fails on an unexpected call to a wrapped symbol, which is what pins that. */
static void test_none_with_readable_ca_is_not_probed(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_NONE, "etc/operator-ca.pem");

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

/* The case the shipped template creates: a CA path that parses cleanly and is never read.
 * It stays silent, because 'none' means the value has no effect -- it becomes a (4118)
 * refusal the moment someone turns verification on, and not before. */
static void test_none_with_unreadable_ca_is_not_probed_either(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_NONE, "PATH");

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

/* --- verifying modes: an unusable CA must stop the start, not be worked around --- */

static void test_full_with_readable_ca_starts(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_FULL, "etc/operator-ca.pem");

    expect_ca_readable("etc/operator-ca.pem", 1);

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

/* --- verification_mode system: trusts the OS store, never a configured CA --- */

static void test_system_without_ca_starts_when_bundle_found(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_SYSTEM, NULL);

    expect_os_find_ca_bundle("/etc/ssl/certs/ca-certificates.crt");

    assert_true(w_agent_validate_ssl_ca(&cfg));
}

static void test_system_without_ca_fails_when_no_bundle_found(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_SYSTEM, NULL);

    expect_os_find_ca_bundle(NULL);
    expect_string(__wrap__merror, formatted_msg,
                  "(4121): <ssl><verification_mode> is 'system' but no OS CA bundle was found "
                  "on this host.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
}

/* A configured CA would simply go unused under 'system' -- reject rather than
 * silently ignore what looks like a real operator intent. */
static void test_system_with_ca_set_fails(void **state)
{
    (void)state;
    agent cfg = make_config(AGENT_VERIFY_SYSTEM, "etc/operator-ca.pem");

    expect_string(__wrap__merror, formatted_msg,
                  "(4120): <ssl><verification_mode> is 'system' but <certificate_authorities> is "
                  "set: 'etc/operator-ca.pem'. Remove it, or choose a different "
                  "verification_mode; the OS trust store is used instead.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
}

/* --- w_agent_resolve_ssl_posture(): no <verification_mode> at all --- */

/* Nothing configured and no anchor: there is no trust material, so there is nothing to
 * verify against. 'system' would only refuse to connect against a stock manager. */
static void test_resolve_unset_without_ca_without_anchor_is_none(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, NULL);

    expect_anchor(0);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_null(cfg.ssl.certificate_authorities);
    free_config(&cfg);
}

static void test_resolve_unset_without_ca_with_anchor_is_full_on_the_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, NULL);

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate_authorities, AGENT_ANCHOR_CA);
    free_config(&cfg);
}

/* A configured CA is the operator saying what to trust, so it settles the mode before the
 * anchor is considered -- with or without an anchor on disk. */
static void test_resolve_unset_with_ca_is_certificate_without_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, "etc/operator-ca.pem");

    expect_anchor(0);
    expect_inferred_certificate();

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);
    assert_string_equal(cfg.ssl.certificate_authorities, "etc/operator-ca.pem");
    free_config(&cfg);
}

static void test_resolve_unset_with_ca_is_certificate_with_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, "etc/operator-ca.pem");

    expect_anchor(1);
    expect_inferred_certificate();

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);
    assert_string_equal(cfg.ssl.certificate_authorities, "etc/operator-ca.pem");
    free_config(&cfg);
}

/* <certificate_authorities/> parses into an empty string, which is not a CA: it must not
 * infer 'certificate', and it must not block the anchor from filling the gap. */
static void test_resolve_unset_with_empty_ca_is_none(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, "");

    expect_anchor(0);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_string_equal(cfg.ssl.certificate_authorities, "");
    free_config(&cfg);
}

static void test_resolve_unset_with_empty_ca_and_anchor_replaces_it(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, "");

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate_authorities, AGENT_ANCHOR_CA);
    free_config(&cfg);
}

/* --- explicit verifying modes: honoured, and the anchor only fills a missing CA --- */

static void test_resolve_full_with_ca_is_untouched(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_FULL, "etc/operator-ca.pem");

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate_authorities, "etc/operator-ca.pem");
    free_config(&cfg);
}

/* The state w_agent_validate_ssl_ca() turns into (4118). */
static void test_resolve_full_without_ca_without_anchor_stays_bare(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_FULL, NULL);

    expect_anchor(0);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_null(cfg.ssl.certificate_authorities);
    free_config(&cfg);
}

static void test_resolve_full_without_ca_with_anchor_gets_the_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_FULL, NULL);

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate_authorities, AGENT_ANCHOR_CA);
    free_config(&cfg);
}

/* Separate from the 'full' row above: the injection covers both verifying modes, and a
 * condition written for FULL alone is the obvious way to get this wrong. */
static void test_resolve_certificate_without_ca_with_anchor_gets_the_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_CERT, NULL);

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);
    assert_string_equal(cfg.ssl.certificate_authorities, AGENT_ANCHOR_CA);
    free_config(&cfg);
}

static void test_resolve_certificate_with_ca_is_untouched(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_CERT, "etc/operator-ca.pem");

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);
    assert_string_equal(cfg.ssl.certificate_authorities, "etc/operator-ca.pem");
    free_config(&cfg);
}

/* 'system' anchors on the OS store, and a CA set alongside it is a hard (4120) refusal --
 * so injecting the anchor here would stop every agent that holds one from starting. */
static void test_resolve_system_never_takes_the_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_SYSTEM, NULL);

    expect_anchor(1);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_SYSTEM);
    assert_null(cfg.ssl.certificate_authorities);
    free_config(&cfg);
}

/* --- an explicit 'none' with an anchor on disk: honoured, and said out loud --- */

static void test_resolve_none_without_anchor_is_kept(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_NONE, NULL);

    expect_anchor(0);

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_null(cfg.ssl.certificate_authorities);
    free_config(&cfg);
}

/* The anchor is a default, not an override: an operator who asks for 'none' gets 'none',
 * without also having to delete the file. (4122) records that the host could have verified. */
static void test_resolve_none_with_anchor_is_still_none(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_NONE, NULL);

    expect_anchor(1);
    expect_none_ignores_anchor();

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_null(cfg.ssl.certificate_authorities);
    free_config(&cfg);
}

/* The shape a configuration-management default actually leaves behind: 'none' next to a CA
 * path nobody maintains, because under 'none' it was never read. Both survive untouched --
 * the resolver injects nothing into a mode that opens no CA, so a later switch to 'full'
 * verifies against the operator's own path and not against something put there for them. */
static void test_resolve_none_with_anchor_keeps_the_configured_ca(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_NONE, "etc/operator-ca.pem");

    expect_anchor(1);
    expect_none_ignores_anchor();

    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_string_equal(cfg.ssl.certificate_authorities, "etc/operator-ca.pem");
    free_config(&cfg);
}

/* Nothing calls it twice today. A phase-2 caller that re-resolves after writing the anchor
 * will, and must not double-allocate or re-log. */
static void test_resolve_is_idempotent(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, NULL);

    expect_anchor(1);
    w_agent_resolve_ssl_posture(&cfg);

    expect_anchor(1);
    w_agent_resolve_ssl_posture(&cfg);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate_authorities, AGENT_ANCHOR_CA);
    free_config(&cfg);
}

/* --- resolver and validator composed: what the agent actually does at start-up --- */

/* Both probes carry AGENT_ANCHOR_CA: the resolver's, then the validator's on the path the
 * resolver just injected. One expectation would fail on the second call. */
static void test_anchor_default_posture_starts(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_UNSET, NULL);

    expect_anchor(1);
    w_agent_resolve_ssl_posture(&cfg);

    expect_anchor(1);
    assert_true(w_agent_validate_ssl_ca(&cfg));

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    free_config(&cfg);
}

/* No second probe: the validator short-circuits on a NULL CA before reaching w_is_file(). */
static void test_full_without_ca_without_anchor_refuses_to_start(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_FULL, NULL);

    expect_anchor(0);
    w_agent_resolve_ssl_posture(&cfg);

    expect_string(__wrap__merror, formatted_msg,
                  "(4118): <ssl><verification_mode> is not 'none' but <certificate_authorities> "
                  "is missing or unreadable: ''.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
    free_config(&cfg);
}

/* An anchor does not rescue 'system': that mode wants the OS store, and without one the
 * agent still refuses. */
static void test_system_with_anchor_still_needs_an_os_bundle(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_SYSTEM, NULL);

    expect_anchor(1);
    w_agent_resolve_ssl_posture(&cfg);

    expect_os_find_ca_bundle(NULL);
    expect_string(__wrap__merror, formatted_msg,
                  "(4121): <ssl><verification_mode> is 'system' but no OS CA bundle was found "
                  "on this host.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_SYSTEM);
    free_config(&cfg);
}

/* An anchor on disk must not become a reason to refuse, in either direction: the agent
 * starts, and it starts with verification off, because that is what was configured. */
static void test_none_with_anchor_starts_without_verifying(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_NONE, NULL);

    expect_anchor(1);
    expect_none_ignores_anchor();
    w_agent_resolve_ssl_posture(&cfg);

    assert_true(w_agent_validate_ssl_ca(&cfg));

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_null(cfg.ssl.certificate_authorities);
    free_config(&cfg);
}

/* The one row where the anchor deliberately does not keep the agent on the air: an explicit
 * verifying mode names a CA that cannot be opened. The named (4118) wins -- silently
 * verifying against an anchor the operator never pointed at would hide the broken path
 * instead of reporting it. */
static void test_full_with_unreadable_ca_still_refuses_with_an_anchor(void **state)
{
    (void)state;
    agent cfg = make_config_heap(AGENT_VERIFY_FULL, "etc/operator-ca.pem");

    expect_anchor(1);
    w_agent_resolve_ssl_posture(&cfg);

    assert_string_equal(cfg.ssl.certificate_authorities, "etc/operator-ca.pem");

    expect_ca_readable("etc/operator-ca.pem", 0);
    expect_string(__wrap__merror, formatted_msg,
                  "(4118): <ssl><verification_mode> is not 'none' but <certificate_authorities> "
                  "is missing or unreadable: 'etc/operator-ca.pem'.");

    assert_false(w_agent_validate_ssl_ca(&cfg));
    free_config(&cfg);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_none_without_ca_starts_quietly),
        cmocka_unit_test(test_none_with_readable_ca_is_not_probed),
        cmocka_unit_test(test_none_with_unreadable_ca_is_not_probed_either),
        cmocka_unit_test(test_full_with_readable_ca_starts),
        cmocka_unit_test(test_full_with_unreadable_ca_fails),
        cmocka_unit_test(test_full_without_ca_fails),
        cmocka_unit_test(test_certificate_with_unreadable_ca_fails),
        cmocka_unit_test(test_system_without_ca_starts_when_bundle_found),
        cmocka_unit_test(test_system_without_ca_fails_when_no_bundle_found),
        cmocka_unit_test(test_system_with_ca_set_fails),

        /* Mode resolution: one per row of the <ssl> resolution matrix. An invalid
         * <verification_mode> has no row here -- Read_Agent_SSL() rejects it with (1235) and
         * ClientConf() returns before the resolver ever runs, which
         * test_client-config_https.c already covers. */
        cmocka_unit_test(test_resolve_unset_without_ca_without_anchor_is_none),
        cmocka_unit_test(test_resolve_unset_without_ca_with_anchor_is_full_on_the_anchor),
        cmocka_unit_test(test_resolve_unset_with_ca_is_certificate_without_anchor),
        cmocka_unit_test(test_resolve_unset_with_ca_is_certificate_with_anchor),
        cmocka_unit_test(test_resolve_unset_with_empty_ca_is_none),
        cmocka_unit_test(test_resolve_unset_with_empty_ca_and_anchor_replaces_it),
        cmocka_unit_test(test_resolve_full_with_ca_is_untouched),
        cmocka_unit_test(test_resolve_full_without_ca_without_anchor_stays_bare),
        cmocka_unit_test(test_resolve_full_without_ca_with_anchor_gets_the_anchor),
        cmocka_unit_test(test_resolve_certificate_without_ca_with_anchor_gets_the_anchor),
        cmocka_unit_test(test_resolve_certificate_with_ca_is_untouched),
        cmocka_unit_test(test_resolve_system_never_takes_the_anchor),
        cmocka_unit_test(test_resolve_none_without_anchor_is_kept),
        cmocka_unit_test(test_resolve_none_with_anchor_is_still_none),
        cmocka_unit_test(test_resolve_none_with_anchor_keeps_the_configured_ca),
        cmocka_unit_test(test_resolve_is_idempotent),

        /* Resolver and validator composed. */
        cmocka_unit_test(test_anchor_default_posture_starts),
        cmocka_unit_test(test_full_without_ca_without_anchor_refuses_to_start),
        cmocka_unit_test(test_system_with_anchor_still_needs_an_os_bundle),
        cmocka_unit_test(test_none_with_anchor_starts_without_verifying),
        cmocka_unit_test(test_full_with_unreadable_ca_still_refuses_with_an_anchor),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

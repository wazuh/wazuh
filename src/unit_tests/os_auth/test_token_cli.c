/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The enrollment token utility mode of wazuh-manager-authd (token_cli.c, issue #38993): the option
// table main() hands to getopt_long(), the requests the four actions send over auth.sock (the
// socket is wrapped, so the JSON that leaves the CLI and the answer it gets are both under test)
// and what reaches stdout and stderr. --show-token runs the real codec over the frozen E4 token.

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "shared.h"
#include "token_cli.h"
#include "enrollment_token_store.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

// The short options main() uses, so the table walk below sees exactly what the daemon sees.
#define AUTHD_SHORT_OPTS "Vdhtfu:g:D:p:c:v:sx:k:P"
#define FAKE_SOCK 1000
#define TOKEN_ID "AAECAwQFBgcICQoLDA0ODw"
// test_vectors::enroll_token::kTokenWithKey (E4): adr siem.example.local, pin 6091dc36..0aa2, id 00..0f, secret 10..1f.
#define FROZEN_TOKEN "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NOGpaUmZrLXVfRkxOd0lNenVkek5PUkplc0x2TlpDcUkiLCJrZXkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4In0"
#define FROZEN_PIN_HEX "6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2"
#define FROZEN_SECRET_B64 "EBESExQVFhcYGRobHB0eHw"

/* ------------------------------------------------------------------ helpers */

// Walks argv through getopt_long() the way main() does. Returns the last value
// w_token_cli_parse_opt() gave (1 consumed, 0 not ours, -1 error) and stops at the first error.
static int parse_argv(token_cli_opts_t *opts, FILE *err, int argc, char **argv) {
    int c;
    int result = 1;

    memset(opts, 0, sizeof(*opts));
    optind = 0; // GNU: reinitialise getopt between walks
    opterr = 0;

    while (c = getopt_long(argc, argv, AUTHD_SHORT_OPTS, token_cli_long_opts, NULL), c != -1) {
        result = w_token_cli_parse_opt(opts, c, optarg, err);
        if (result < 0) {
            break;
        }
    }

    return result;
}

typedef struct {
    FILE *out;
    FILE *err;
    char *out_buf;
    char *err_buf;
    size_t out_len;
    size_t err_len;
} streams_t;

static void streams_open(streams_t *s) {
    memset(s, 0, sizeof(*s));
    s->out = open_memstream(&s->out_buf, &s->out_len);
    s->err = open_memstream(&s->err_buf, &s->err_len);
    assert_non_null(s->out);
    assert_non_null(s->err);
}

static void streams_close(streams_t *s) {
    fclose(s->out);
    fclose(s->err);
}

static void streams_free(streams_t *s) {
    free(s->out_buf);
    free(s->err_buf);
}

// One request/response exchange over the wrapped socket.
static void expect_exchange(const char *expected_request, const char *response) {
    expect_string(__wrap_OS_ConnectUnixDomain, path, AUTH_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, FAKE_SOCK);
    expect_value(__wrap_OS_SendSecureTCP, sock, FAKE_SOCK);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(expected_request));
    expect_string(__wrap_OS_SendSecureTCP, msg, expected_request);
    will_return(__wrap_OS_SendSecureTCP, 0);
    expect_value(__wrap_OS_RecvSecureTCP, sock, FAKE_SOCK);
    expect_value(__wrap_OS_RecvSecureTCP, size, TOKEN_CLI_MAX_REPLY);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, (int)strlen(response));
}

/* ------------------------------------------------------------------ parsing */

static void test_parse_actions_and_suboptions(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    streams_open(&s);

    char *create[] = {"authd", "--create-enrollment-token", "--address", "wazuh-1", "--ttl", "1h", "--max-uses", "3",
                      "--description", "ci", "--port", "8443", "--prefix", "gw", "--embed-ca", "--no-credential"};
    assert_int_equal(parse_argv(&opts, s.err, 16, create), 1);
    assert_true(opts.requested);
    assert_int_equal(opts.action, TOKEN_CLI_CREATE);
    assert_string_equal(opts.address, "wazuh-1");
    assert_int_equal(opts.ttl, 3600);
    assert_int_equal(opts.max_uses, 3);
    assert_string_equal(opts.description, "ci");
    assert_int_equal(opts.port, 8443);
    assert_string_equal(opts.prefix, "gw");
    assert_true(opts.embed_ca);
    assert_true(opts.no_credential);

    char *days[] = {"authd", "--create-enrollment-token", "--ttl", "30d"};
    assert_int_equal(parse_argv(&opts, s.err, 4, days), 1);
    assert_int_equal(opts.ttl, 2592000);

    char *list[] = {"authd", "--list-enrollment-tokens"};
    assert_int_equal(parse_argv(&opts, s.err, 2, list), 1);
    assert_int_equal(opts.action, TOKEN_CLI_LIST);

    char *revoke[] = {"authd", "--revoke-enrollment-token", TOKEN_ID};
    assert_int_equal(parse_argv(&opts, s.err, 3, revoke), 1);
    assert_int_equal(opts.action, TOKEN_CLI_REVOKE);
    assert_string_equal(opts.revoke_id, TOKEN_ID);

    char *show[] = {"authd", "--show-token=" FROZEN_TOKEN};
    assert_int_equal(parse_argv(&opts, s.err, 2, show), 1);
    assert_int_equal(opts.action, TOKEN_CLI_SHOW);
    assert_string_equal(opts.token_text, FROZEN_TOKEN);

    char *show_file[] = {"authd", "--show-token", "--token-file", "/tmp/t"};
    assert_int_equal(parse_argv(&opts, s.err, 4, show_file), 1);
    assert_int_equal(opts.action, TOKEN_CLI_SHOW);
    assert_null(opts.token_text);
    assert_string_equal(opts.token_file, "/tmp/t");

    // A daemon option is not ours: main() keeps handling it.
    char *daemon[] = {"authd", "-d"};
    assert_int_equal(parse_argv(&opts, s.err, 2, daemon), 0);
    assert_false(opts.requested);

    // Invalid values and two actions are refused with a message.
    char *ttl_zero[] = {"authd", "--create-enrollment-token", "--ttl", "0"};
    assert_int_equal(parse_argv(&opts, s.err, 4, ttl_zero), -1);
    char *ttl_bad[] = {"authd", "--create-enrollment-token", "--ttl", "x"};
    assert_int_equal(parse_argv(&opts, s.err, 4, ttl_bad), -1);
    // A duration whose unit does not fit a time_t: get_time_interval() refuses the multiplication
    // instead of wrapping it into a number that no longer says what was typed.
    char *ttl_overflow[] = {"authd", "--create-enrollment-token", "--ttl", "999999999999999d"};
    assert_int_equal(parse_argv(&opts, s.err, 4, ttl_overflow), -1);
    // Representable, but past what a token's expiry may be: refused here so the operator does not
    // have to send the request and read a 9025 back.
    char *ttl_over_cap[] = {"authd", "--create-enrollment-token", "--ttl", "3651d"};
    assert_int_equal(parse_argv(&opts, s.err, 4, ttl_over_cap), -1);
    // The ceiling itself is accepted: what is refused is what cannot be stored, not a long life.
    char *ttl_cap[] = {"authd", "--create-enrollment-token", "--ttl", "3650d"};
    assert_int_equal(parse_argv(&opts, s.err, 4, ttl_cap), 1);
    assert_int_equal(opts.ttl, ETOKEN_MAX_TTL);
    char *port_bad[] = {"authd", "--create-enrollment-token", "--port", "70000"};
    assert_int_equal(parse_argv(&opts, s.err, 4, port_bad), -1);
    char *uses_bad[] = {"authd", "--create-enrollment-token", "--max-uses", "-1"};
    assert_int_equal(parse_argv(&opts, s.err, 4, uses_bad), -1);
    char *two[] = {"authd", "--create-enrollment-token", "--list-enrollment-tokens"};
    assert_int_equal(parse_argv(&opts, s.err, 3, two), -1);

    streams_close(&s);
    assert_non_null(strstr(s.err_buf, "--ttl must be a positive duration"));
    assert_non_null(strstr(s.err_buf, "--ttl must not exceed 315360000 seconds"));
    assert_non_null(strstr(s.err_buf, "--port must be between 1 and 65535"));
    assert_non_null(strstr(s.err_buf, "--max-uses needs a numeric argument"));
    assert_non_null(strstr(s.err_buf, "only one of"));
    streams_free(&s);
}

/* ------------------------------------------------------------------ create */

static void test_create_sends_the_request_and_prints_only_the_token(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--create-enrollment-token", "--address", "wazuh-1", "--ttl", "1h", "--max-uses", "3",
                    "--description", "ci"};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 10, argv), 1);

    expect_exchange("{\"arguments\":{\"address\":\"wazuh-1\",\"ttl\":3600,\"max_uses\":3,\"description\":\"ci\"},\"function\":\"token_create\"}",
                    "{\"error\":0,\"data\":{\"token\":\"T\",\"id\":\"I\",\"adr\":\"wazuh-1\",\"expires\":1800000000,\"pin_hex\":\"" FROZEN_PIN_HEX "\"}}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);

    // stdout is the token and nothing else: `WAZUH_ENROLLMENT_TOKEN=$(...)` captures exactly it.
    assert_string_equal(s.out_buf, "T\n");
    assert_non_null(strstr(s.err_buf, "id: I\n"));
    assert_non_null(strstr(s.err_buf, "endpoint: wazuh-1\n"));
    assert_non_null(strstr(s.err_buf, "expires: 2027-01-15T08:00:00Z (1800000000)\n"));
    assert_non_null(strstr(s.err_buf, "pin: " FROZEN_PIN_HEX "\n"));
    assert_non_null(strstr(s.err_buf, "credential: yes\n"));
    streams_free(&s);

    // Flags travel as JSON booleans; port and prefix only when given; no pin_hex with an embedded CA.
    char *argv2[] = {"authd", "--create-enrollment-token", "--address", "127.0.0.1", "--port", "8443", "--prefix", "gw",
                     "--embed-ca", "--no-credential"};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 10, argv2), 1);
    expect_exchange("{\"arguments\":{\"address\":\"127.0.0.1\",\"port\":8443,\"prefix\":\"gw\",\"embed_ca\":true,\"no_credential\":true},\"function\":\"token_create\"}",
                    "{\"error\":0,\"data\":{\"token\":\"T2\",\"id\":\"I2\",\"adr\":\"127.0.0.1:8443/gw\",\"expires\":1800000000}}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_string_equal(s.out_buf, "T2\n");
    assert_null(strstr(s.err_buf, "pin:"));
    assert_non_null(strstr(s.err_buf, "credential: no\n"));
    streams_free(&s);
}

static void test_create_requires_address(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--create-enrollment-token", "--ttl", "1h"};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 4, argv), 1);
    // No socket expectation: the CLI must refuse before connecting.
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_string_equal(s.out_buf, "");
    assert_non_null(strstr(s.err_buf, "--address"));
    streams_free(&s);

    // A sub-option alone, without an action, is an error too.
    char *argv2[] = {"authd", "--address", "wazuh-1"};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 3, argv2), 1);
    assert_true(opts.requested);
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_non_null(strstr(s.err_buf, "without an action"));
    streams_free(&s);
}

static void test_create_reports_authd_errors(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--create-enrollment-token", "--address", "evil"};
    const char *request = "{\"arguments\":{\"address\":\"evil\"},\"function\":\"token_create\"}";

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 4, argv), 1);
    expect_exchange(request, "{\"error\":9025,\"message\":\"Enrollment token refused: address not in certificate SAN\"}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_string_equal(s.out_buf, "");
    assert_non_null(strstr(s.err_buf, "ERROR 9025: Enrollment token refused: address not in certificate SAN\n"));
    assert_null(strstr(s.err_buf, "master node"));
    streams_free(&s);

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 4, argv), 1);
    expect_exchange(request, "{\"error\":9015,\"message\":\"Cannot execute this request on a worker node\"}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_non_null(strstr(s.err_buf, "ERROR 9015: Cannot execute this request on a worker node\n"));
    assert_non_null(strstr(s.err_buf, "master node"));
    streams_free(&s);
}

static void test_connect_failure_is_explained(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--list-enrollment-tokens"};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, argv), 1);
    expect_string(__wrap_OS_ConnectUnixDomain, path, AUTH_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, -1);
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_string_equal(s.out_buf, "");
    assert_non_null(strstr(s.err_buf, "auth.sock"));
    assert_non_null(strstr(s.err_buf, "running"));
    streams_free(&s);
}

/* ------------------------------------------------------------------ list / revoke */

static void test_list_prints_the_table_and_never_the_secret(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--list-enrollment-tokens"};
    const char *request = "{\"function\":\"token_list\"}";

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, argv), 1);
    expect_exchange(request,
                    "{\"error\":0,\"data\":[{\"id\":\"" TOKEN_ID "\",\"adr\":\"wazuh-1\",\"created\":1,\"expires\":1800000000,"
                    "\"max_uses\":3,\"uses\":1,\"revoked\":false,\"credential\":true,\"description\":\"ci\"},"
                    "{\"id\":\"" FROZEN_SECRET_B64 "\",\"adr\":\"h/\",\"created\":1,\"expires\":1800000000,"
                    "\"max_uses\":0,\"uses\":0,\"revoked\":true,\"credential\":false,\"description\":null}]}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_non_null(strstr(s.out_buf, "ID  "));
    assert_non_null(strstr(s.out_buf, "ENDPOINT"));
    assert_non_null(strstr(s.out_buf, TOKEN_ID "  "));
    assert_non_null(strstr(s.out_buf, "2027-01-15T08:00:00Z"));
    assert_non_null(strstr(s.out_buf, "  1/3  "));
    assert_non_null(strstr(s.out_buf, "  0/unlimited  "));
    assert_non_null(strstr(s.out_buf, "  no       ci\n"));
    assert_non_null(strstr(s.out_buf, "  yes      -\n"));
    assert_null(strstr(s.out_buf, "secret"));
    assert_string_equal(s.err_buf, "");
    streams_free(&s);

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, argv), 1);
    expect_exchange(request, "{\"error\":0,\"data\":[]}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_string_equal(s.out_buf, "no enrollment tokens\n");
    streams_free(&s);
}

static void test_revoke_ok_and_unknown(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--revoke-enrollment-token", TOKEN_ID};
    const char *request = "{\"arguments\":{\"id\":\"" TOKEN_ID "\"},\"function\":\"token_revoke\"}";

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 3, argv), 1);
    expect_exchange(request, "{\"error\":0,\"data\":{}}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_string_equal(s.out_buf, "Enrollment token " TOKEN_ID " revoked.\n");
    streams_free(&s);

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 3, argv), 1);
    expect_exchange(request, "{\"error\":9022,\"message\":\"Enrollment token not found or revoked\"}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_string_equal(s.out_buf, "");
    assert_non_null(strstr(s.err_buf, "ERROR 9022: Enrollment token not found or revoked\n"));
    streams_free(&s);

    // A storage failure is its own answer (issue #39078, H04): the token exists and authd already
    // refuses it, so the operator has to retry the write, not go looking for the id.
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 3, argv), 1);
    expect_exchange(request, "{\"error\":9029,\"message\":\"Enrollment token store write failed\"}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_string_equal(s.out_buf, "");
    assert_non_null(strstr(s.err_buf, "ERROR 9029: Enrollment token store write failed\n"));
    streams_free(&s);
}

/* ------------------------------------------------------------------ purge */

static void test_purge_dead_is_the_default(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--purge-enrollment-tokens"};
    const char *request = "{\"arguments\":{\"scope\":\"dead\"},\"function\":\"token_purge\"}";

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, argv), 1);
    expect_exchange(request, "{\"error\":0,\"data\":{\"removed\":3,\"remaining\":7,\"ids\":[]}}");
    // No --all, so nothing is asked: dropping tokens that can no longer enrol anybody is not a
    // decision an operator needs to confirm.
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_string_equal(s.out_buf, "Removed 3 enrollment token(s); 7 left.\n");
    streams_free(&s);
}

static void test_purge_all_asks_before_emptying_the_store(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--purge-enrollment-tokens", "--all"};
    FILE *answer = NULL;

    // stdin is not a terminal here, so the confirmation cannot be given: the CLI refuses instead of
    // taking silence for a yes, and says which flag a script should use.
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 3, argv), 1);
    answer = fmemopen((void *)"y\n", 2, "r");
    assert_non_null(answer);
    assert_int_equal(w_token_cli_run(&opts, answer, s.out, s.err), 1);
    fclose(answer);
    streams_close(&s);
    assert_non_null(strstr(s.err_buf, "--force"));
    assert_string_equal(s.out_buf, "");
    streams_free(&s);
}

static void test_purge_all_with_force_sends_the_wider_scope(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--purge-enrollment-tokens", "--all", "--force"};
    const char *request = "{\"arguments\":{\"scope\":\"all\"},\"function\":\"token_purge\"}";

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 4, argv), 1);
    expect_exchange(request, "{\"error\":0,\"data\":{\"removed\":10,\"remaining\":0,\"ids\":[]}}");
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_string_equal(s.out_buf, "Removed 10 enrollment token(s); 0 left.\n");
    streams_free(&s);
}

static void test_purge_of_a_full_store_is_read_back_whole(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--purge-enrollment-tokens"};
    const char *request = "{\"arguments\":{\"scope\":\"dead\"},\"function\":\"token_purge\"}";
    char *reply = NULL;
    size_t used = 0;
    int i;

    // What emptying a full store answers: one id per token, ~122 KB, well past the 64 KB the socket
    // helpers default to. Read short, the purge would look like a failure although it had happened.
    os_calloc(TOKEN_CLI_MAX_REPLY, sizeof(char), reply);
    used = (size_t)snprintf(reply, TOKEN_CLI_MAX_REPLY,
                            "{\"error\":0,\"data\":{\"removed\":%d,\"remaining\":0,\"ids\":[", ETOKEN_MAX_TOKENS);

    for (i = 0; i < ETOKEN_MAX_TOKENS; i++) {
        used += (size_t)snprintf(reply + used, TOKEN_CLI_MAX_REPLY - used, "%s\"%.*d\"",
                                 i ? "," : "", ETOKEN_ID_CHARS, i);
    }

    snprintf(reply + used, TOKEN_CLI_MAX_REPLY - used, "]}}");
    assert_true(strlen(reply) > OS_MAXSTR);

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, argv), 1);
    expect_exchange(request, reply);
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_string_equal(s.out_buf, "Removed 5000 enrollment token(s); 0 left.\n");
    assert_string_equal(s.err_buf, "");
    streams_free(&s);
    os_free(reply);
}

static void test_a_reply_that_does_not_fit_is_not_reported_as_silence(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char *argv[] = {"authd", "--purge-enrollment-tokens"};
    const char *request = "{\"arguments\":{\"scope\":\"dead\"},\"function\":\"token_purge\"}";

    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, argv), 1);
    expect_string(__wrap_OS_ConnectUnixDomain, path, AUTH_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, FAKE_SOCK);
    expect_value(__wrap_OS_SendSecureTCP, sock, FAKE_SOCK);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(request));
    expect_string(__wrap_OS_SendSecureTCP, msg, request);
    will_return(__wrap_OS_SendSecureTCP, 0);
    expect_value(__wrap_OS_RecvSecureTCP, sock, FAKE_SOCK);
    expect_value(__wrap_OS_RecvSecureTCP, size, TOKEN_CLI_MAX_REPLY);
    will_return(__wrap_OS_RecvSecureTCP, "");
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    // authd answered, this side could not take the answer in: the operator is told the request may
    // already have been applied instead of being invited to retry it.
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_non_null(strstr(s.err_buf, "too large"));
    assert_null(strstr(s.err_buf, "no response"));
    streams_free(&s);
}

/* ------------------------------------------------------------------ show */

static void assert_frozen_description(const char *text) {
    assert_non_null(strstr(text, "ver: 1\n"));
    assert_non_null(strstr(text, "adr: siem.example.local\n"));
    assert_non_null(strstr(text, "pin: " FROZEN_PIN_HEX "\n"));
    assert_non_null(strstr(text, "credential: present\n"));
    // Neither the credential nor either of its halves ever reaches the output.
    assert_null(strstr(text, FROZEN_SECRET_B64));
    assert_null(strstr(text, TOKEN_ID));
    assert_null(strstr(text, "key"));
}

static void test_show_token_from_arg_file_and_stdin(void **state) {
    (void)state;
    token_cli_opts_t opts;
    streams_t s;
    char path[] = "/tmp/token_cli_XXXXXX";
    int fd;
    FILE *fp;

    // --show-token=<token>: no socket at all.
    char *arg[] = {"authd", "--show-token=" FROZEN_TOKEN};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, arg), 1);
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_frozen_description(s.out_buf);
    assert_string_equal(s.err_buf, "");
    streams_free(&s);

    // --token-file: first line, whitespace around it ignored.
    fd = mkstemp(path);
    assert_true(fd >= 0);
    fp = fdopen(fd, "w");
    assert_non_null(fp);
    fprintf(fp, "  %s \n\nsecond line ignored\n", FROZEN_TOKEN);
    fclose(fp);
    char *file[] = {"authd", "--show-token", "--token-file", path};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 4, file), 1);
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 0);
    streams_close(&s);
    assert_frozen_description(s.out_buf);
    streams_free(&s);
    unlink(path);

    // stdin (a pipe): the same.
    char *plain[] = {"authd", "--show-token"};
    char piped[] = FROZEN_TOKEN "\n";
    FILE *in = fmemopen(piped, strlen(piped), "r");
    assert_non_null(in);
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, plain), 1);
    assert_int_equal(w_token_cli_run(&opts, in, s.out, s.err), 0);
    streams_close(&s);
    fclose(in);
    assert_frozen_description(s.out_buf);
    streams_free(&s);

    // Garbage and nothing at all are reported, exit 1, nothing on stdout.
    char garbage[] = "!!!\n";
    in = fmemopen(garbage, strlen(garbage), "r");
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, plain), 1);
    assert_int_equal(w_token_cli_run(&opts, in, s.out, s.err), 1);
    streams_close(&s);
    fclose(in);
    assert_string_equal(s.out_buf, "");
    assert_non_null(strstr(s.err_buf, "malformed token"));
    streams_free(&s);

    char empty[] = "\n";
    in = fmemopen(empty, strlen(empty), "r");
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 2, plain), 1);
    assert_int_equal(w_token_cli_run(&opts, in, s.out, s.err), 1);
    streams_close(&s);
    fclose(in);
    assert_non_null(strstr(s.err_buf, "no token given"));
    streams_free(&s);

    char *missing[] = {"authd", "--show-token", "--token-file", "/nonexistent/token"};
    streams_open(&s);
    assert_int_equal(parse_argv(&opts, s.err, 4, missing), 1);
    assert_int_equal(w_token_cli_run(&opts, stdin, s.out, s.err), 1);
    streams_close(&s);
    assert_non_null(strstr(s.err_buf, "cannot read '/nonexistent/token'"));
    streams_free(&s);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_actions_and_suboptions),
        cmocka_unit_test(test_create_sends_the_request_and_prints_only_the_token),
        cmocka_unit_test(test_create_requires_address),
        cmocka_unit_test(test_create_reports_authd_errors),
        cmocka_unit_test(test_connect_failure_is_explained),
        cmocka_unit_test(test_list_prints_the_table_and_never_the_secret),
        cmocka_unit_test(test_revoke_ok_and_unknown),
        cmocka_unit_test(test_purge_dead_is_the_default),
        cmocka_unit_test(test_purge_all_asks_before_emptying_the_store),
        cmocka_unit_test(test_purge_all_with_force_sends_the_wider_scope),
        cmocka_unit_test(test_purge_of_a_full_store_is_read_back_whole),
        cmocka_unit_test(test_a_reply_that_does_not_fit_is_not_reported_as_silence),
        cmocka_unit_test(test_show_token_from_arg_file_and_stdin),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

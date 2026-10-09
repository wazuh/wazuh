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
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>

#include "shared.h"
#include "agentd.h"
#include "agent_auth_cli.h"
#include "token_bootstrap.h"
#include "enrollment_token.h"
#include "https_client.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Exported only under WAZUH_UNIT_TESTING (agent_auth_cli.c's STATIC), so it needs a prototype
 * here rather than in the public header -- the config rewrite is internal to the command. */
int w_agent_auth_update_endpoint(const char *adr, const char *configured, FILE *err);

/* Frozen tokens. Held as literals rather than built at run time so a change to the encoder
 * shows up here as a decode failure instead of being silently re-encoded into agreement. */
#define TOKEN_PIN_ONLY "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDgifQ"
#define TOKEN_WITH_KEY "eyJ2ZXIiOjEsImFkciI6Im5ldy5leGFtcGxlLmxvY2FsOjE1MTgiLCJwaW4iOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4Iiwia2V5IjoiWkdWbVoyaHBhbXRzYlc1dmNIRnljM1IxZG5kNGVYcDdmSDEtZjRDQmdvTSJ9"
#define FROZEN_PIN_HEX "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
/* The credential's own base64url. Nothing that renders a token may ever emit this. */
#define FROZEN_KEY_B64 "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM"
#define FROZEN_ID_B64  "ZGVmZ2hpamtsbW5vcHFycw"

/* The agentd pid the running-agent probe is meant to find. */
#define FAKE_AGENTD_PID 4711

/* One spelling of the existing key, so a test can assert the file is byte-for-byte unchanged
 * rather than merely present. */
#define EXISTING_KEY_LINE "003 web-01 any abcdef0123456789\n"

/* An ossec.conf carrying the address setup_test() reports as configured, and what the rewrite
 * turns it into. The read-back guard in w_agent_auth_update_endpoint() parses the second one,
 * so it has to be real XML with the node actually changed -- an unchanged copy is the failure
 * it exists to catch. */
#define CONFIG_WITH_ENDPOINT \
    "<ossec_config><agent><manager><endpoint>siem.example.local</endpoint></manager>" \
    "</agent></ossec_config>\n"
#define REWRITTEN_CONFIG \
    "<ossec_config><agent><manager><endpoint>new.example.local:1518</endpoint></manager>" \
    "</agent></ossec_config>\n"

static bool g_agentd_alive = false;

/* kill(pid, 0) is the liveness probe; everything else must reach the real one, or cmocka's own
 * signal handling goes through this wrapper too. */
int __wrap_kill(pid_t pid, int sig) {
    int __real_kill(pid_t pid, int sig);

    if (sig != 0) {
        return __real_kill(pid, sig);
    }

    if (g_agentd_alive && pid == FAKE_AGENTD_PID) {
        return 0;
    }

    errno = ESRCH;
    return -1;
}


/* --- the host the suite must not depend on ------------------------------------------------
 *
 * The command resolves the account the agent will run as, and refuses before contacting
 * anything when it cannot. Unwrapped, that made the five tests that reach the enrollment core
 * pass on any machine with an agent installed and fail on a clean CI runner, where there is no
 * `wazuh` user or group -- a green suite locally and five exit-code-1 failures in CI, for a
 * reason nothing in the assertions named.
 *
 * The ownership calls go with it. They are the other half of the same dependency: chown()ing a
 * file to root needs root, so leaving them real would swap the CI failure for an unexpected
 * merror() the moment the lookups were fixed. Recording nothing and reporting success is enough
 * here -- test_token_bootstrap.c is where what gets chowned to whom is asserted. */
int __wrap_Privsep_GetUser(__attribute__((unused)) const char *name) {
    return (int) getuid();
}

int __wrap_Privsep_GetGroup(__attribute__((unused)) const char *name) {
    return (int) getgid();
}

/* Counted so the config rewrite can be held to setting the staged file's owner through its
 * descriptor: a chown() by name follows whatever the name points at by then. The inode is what
 * says which file the owner would have landed on. */
static int g_chown_calls = 0;
static int g_fchown_calls = 0;
static uid_t g_fchown_owner = (uid_t) -1;
static gid_t g_fchown_group = (gid_t) -1;
static ino_t g_fchown_ino = 0;

int __wrap_chown(__attribute__((unused)) const char *path, __attribute__((unused)) uid_t owner,
                 __attribute__((unused)) gid_t group) {
    g_chown_calls++;
    return 0;
}

int __wrap_fchown(int fd, uid_t owner, gid_t group) {
    struct stat st;

    g_fchown_calls++;
    g_fchown_owner = owner;
    g_fchown_group = group;
    g_fchown_ino = (fstat(fd, &st) == 0) ? st.st_ino : 0;
    return 0;
}

/* Same reason as chown(): a mode set by name lands on whatever the name points at. */
static int g_fchmodat_calls = 0;

int __real_fchmodat(int dirfd, const char *path, mode_t mode, int flags);

int __wrap_fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    g_fchmodat_calls++;
    return __real_fchmodat(dirfd, path, mode, flags);
}

/* Plays the account that can write etc/ winning the race for the staged copy of ossec.conf: the
 * moment TempFile() has created it, the name is swapped for a symlink to SWAP_TARGET. The stream
 * TempFile() returned still refers to the file it created. */
#define SWAP_TARGET "etc/swap-target"
#define SWAP_TARGET_CONTENT "not ossec.conf\n"

static bool g_swap_staged = false;

/* The name TempFile() chose, for the hooks below that act on it later. */
static char g_staged_name[PATH_MAX] = {0};

int __real_TempFile(File *file, const char *source, int copy);

int __wrap_TempFile(File *file, const char *source, int copy) {
    int result = __real_TempFile(file, source, copy);

    if (result == 0) {
        snprintf(g_staged_name, sizeof(g_staged_name), "%s", file->name);
    }

    if (result == 0 && g_swap_staged) {
        assert_int_equal(unlink(file->name), 0);
        /* Relative to the link's own directory, etc/. */
        assert_int_equal(symlink("swap-target", file->name), 0);
    }

    return result;
}

/* The same account, later: once every check on the staged copy has passed, it puts a directory at
 * the staged name, so rename() cannot move it, and points ossec.conf itself at SWAP_TARGET. A
 * failed move must stay a failure; anything that falls back to copying by name would open
 * ossec.conf for writing and truncate the target as root. */
static bool g_swap_at_rename = false;

int __real_rename(const char *oldpath, const char *newpath);

int __wrap_rename(const char *oldpath, const char *newpath) {
    if (g_swap_at_rename && strcmp(newpath, WAZUHCONF) == 0) {
        g_swap_at_rename = false;
        assert_int_equal(unlink(oldpath), 0);
        assert_int_equal(mkdir(oldpath, 0700), 0);
        assert_int_equal(unlink(newpath), 0);
        assert_int_equal(symlink("swap-target", newpath), 0);
    }

    return __real_rename(oldpath, newpath);
}

/* Puts things back after the hook above: the directory left at the staged name, and the link at
 * ossec.conf, which the next test's write_file() would otherwise follow. */
static void undo_swap_at_rename(void) {
    struct stat st;

    if (g_staged_name[0] != '\0') {
        rmdir(g_staged_name);
    }

    if (lstat(WAZUHCONF, &st) == 0 && S_ISLNK(st.st_mode)) {
        unlink(WAZUHCONF);
    }
}

/* Counts reads of the staged copy by name. Its name can be swapped for a symlink at any time, and
 * root opening it -- even only to read -- then opens whatever the link points at: a FIFO blocks
 * the command, and some device nodes act on open. */
static int g_staged_reads_by_name = 0;

int __real_OS_ReadXML(const char *file, OS_XML *lxml);

int __wrap_OS_ReadXML(const char *file, OS_XML *lxml) {
    if (g_staged_name[0] != '\0' && strcmp(file, g_staged_name) == 0) {
        g_staged_reads_by_name++;
    }

    return __real_OS_ReadXML(file, lxml);
}


/* --- the https_client boundary, mocked exactly as test_token_bootstrap.c mocks it ---------- */

#define PINNED_CERT "PINNED-CERT-ONLY"

static int g_fetch_calls = 0;
static int g_enroll_calls = 0;
static char g_enroll_body[4096] = {0};

bool __wrap_hc_fetch_cacerts(const hc_config_t *config, const hc_cacerts_request_t *request,
                             hc_cacerts_result_t *result) {
    (void) config;
    (void) request;
    g_fetch_calls++;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->http_code = 200;
        strncpy(result->body, "FETCHED-BUNDLE", sizeof(result->body) - 1);
    }

    return true;
}

bool __wrap_hc_spki_pinned_certificate(const char *cacerts_body, size_t body_len,
                                       const char *pin_b64url, char *matched_pem,
                                       size_t matched_pem_size) {
    (void) cacerts_body;
    (void) body_len;
    (void) pin_b64url;

    if (!mock_type(int)) {
        return false;          /* the pin did not match anything in the bundle */
    }

    strncpy(matched_pem, PINNED_CERT, matched_pem_size - 1);
    return true;
}

bool __wrap_hc_enroll(const hc_config_t *config, const hc_enroll_request_t *request,
                      hc_enroll_result_t *result) {
    (void) config;
    g_enroll_calls++;

    if (request) {
        strncpy(g_enroll_body, request->body_json, sizeof(g_enroll_body) - 1);
    }

    if (result) {
        memset(result, 0, sizeof(*result));
        result->http_code = mock_type(long);
        const char *body = (const char *) mock();

        if (body != NULL) {
            strncpy(result->body, body, sizeof(result->body) - 1);
        }
    }

    return mock_type(int) != 0;
}

/* Set by the one test that needs the enrollment to fail at the last step, after the manager has
 * already accepted -- the only way to reach the command's most serious warning. */
static bool g_fail_anchor_move = false;

int __real_OS_MoveFile(const char *src, const char *dst);

int __wrap_OS_MoveFile(const char *src, const char *dst) {
    const char *base = src ? strrchr(src, '/') : NULL;

    base = base ? base + 1 : src;

    if (g_fail_anchor_move && base != NULL && strncmp(base, "root-ca.pem", 11) == 0) {
        return -1;
    }

    return __real_OS_MoveFile(src, dst);
}

/* Set by the test of a write that fails and then recovers. stdio drops a buffer it could not write
 * and keeps only the error flag, so the fflush() and fclose() that follow can both succeed with
 * part of the rewrite gone. */
static bool g_lose_staged_write = false;

static void lose_a_write(FILE *fp_out) {
    char filler[3 * BUFSIZ];
    int fd = fileno(fp_out);
    int saved = dup(fd);

    assert_true(saved >= 0);
    memset(filler, ' ', sizeof(filler));

    /* Larger than the buffer, so it has to reach write(), which fails on the closed descriptor.
     * Nothing opens a file before dup2() puts the descriptor back. */
    close(fd);
    assert_true(fwrite(filler, 1, sizeof(filler), fp_out) < sizeof(filler));
    assert_int_equal(dup2(saved, fd), fd);
    close(saved);
}

int __wrap_OS_WriteXMLToStream(const char *infile, FILE *fp_out, const char **nodes,
                               const char *oldval, const char *newval) {
    (void) infile;
    (void) oldval;

    /* The node PATH is what matters, not the address of the caller's array -- comparing the
     * arrays byte for byte would compare pointers, which differ between translation units. */
    assert_non_null(nodes);
    assert_string_equal(nodes[0], "ossec_config");
    assert_string_equal(nodes[1], "agent");
    assert_string_equal(nodes[2], "manager");
    assert_string_equal(nodes[3], "endpoint");
    assert_null(nodes[4]);
    check_expected(newval);

    /* The real one copies the file through when the node is absent; the caller is supposed to
     * notice by reading the value back, so the mock can simply produce whatever the test wants
     * that read to find. Into the caller's stream, which stays the caller's to flush and close. */
    assert_non_null(fp_out);

    if (g_lose_staged_write) {
        lose_a_write(fp_out);
    }

    fputs((const char *) mock(), fp_out);

    return mock_type(int);
}

/* --- helpers ------------------------------------------------------------------------- */

static void write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    if (content != NULL) {
        fputs(content, fp);
    }
    fclose(fp);
}

/* Drives getopt_long() over an argv the way main-agent-auth.c does, so the option table itself
 * is what is under test -- including the declarations that make an inline token impossible. */
static int parse_argv(agent_auth_opts_t *opts, int argc, char **argv, FILE *err) {
    int c;
    int result = 0;

    w_agent_auth_opts_init(opts);

    optind = 0;
    opterr = 0;

    while ((c = getopt_long(argc, argv, "Vhdn", agent_auth_long_opts, NULL)) != -1) {
        if (c == '?') {
            return -2;   /* getopt_long() refused it: it never reached the module */
        }

        if (c == 'V' || c == 'h' || c == 'd' || c == 'c') {
            continue;    /* main() handles these itself */
        }

        if (w_agent_auth_parse_opt(opts, c, optarg, err) != 0) {
            result = -1;
        }
    }

    return result;
}

/* var/run/wazuh-agentd-<pid>.pid is the shape wazuh-control looks for, and the name is where
 * the pid actually lives (CreatePID(), file_op.c). */
static void seed_agentd_pidfile(pid_t pid) {
    char path[PATH_MAX];

    mkdir("var", 0755);
    mkdir(OS_PIDFILE, 0755);
    snprintf(path, sizeof(path), "%s/wazuh-agentd-%d.pid", OS_PIDFILE, (int) pid);
    write_file(path, "");
}

static void clear_agentd_pidfiles(void) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/wazuh-agentd-%d.pid", OS_PIDFILE, FAKE_AGENTD_PID);
    unlink(path);
}

static int setup_test(void **state) {
    (void) state;

    /* Created here rather than relied upon: every path under test writes into etc/, and the only
     * thing that used to create it was test_token_bootstrap's own setup. That made this suite
     * pass only when the whole directory ran in registration order -- `ctest -R agent_auth` on a
     * clean tree aborted in write_file(). */
    mkdir("etc", 0755);
    mkdir("etc/certs", 0750);

    g_agentd_alive = false;
    g_fetch_calls = 0;
    g_enroll_calls = 0;
    g_enroll_body[0] = '\0';
    g_fail_anchor_move = false;
    g_chown_calls = 0;
    g_fchown_calls = 0;
    g_fchown_owner = (uid_t) -1;
    g_fchown_group = (gid_t) -1;
    g_fchmodat_calls = 0;
    g_fchown_ino = 0;
    g_swap_staged = false;
    g_staged_name[0] = '\0';
    g_swap_at_rename = false;
    g_staged_reads_by_name = 0;
    g_lose_staged_write = false;
    unlink(SWAP_TARGET);
    unlink(KEYS_FILE);
    unlink(AGENT_ANCHOR_CA);
    unlink(AGENT_DELIVERED_CA);
    clear_agentd_pidfiles();

    /* Stands in for ClientConf(): w_agent_auth_run() reads the configured manager out of these
     * globals to tell a re-enrolment apart from a move. */
    os_calloc(1, sizeof(agent), agt);
    os_calloc(2, sizeof(agent_server), agt->server);
    os_strdup("siem.example.local", agt->server[0].rip);
    agt->server[0].port = 1517;
    /* Matches what TOKEN_PIN_ONLY resolves to, so the config rewrite is a no-op unless a test
     * deliberately points the token somewhere else. The rewrite is unconditional now. */
    os_strdup("wazuh-manager", agt->server[0].endpoint);

    return 0;
}

static int teardown_test(void **state) {
    (void) state;
    unlink(KEYS_FILE);
    rmdir(AGENT_DELIVERED_CA);
    unlink(AGENT_DELIVERED_CA);
    rmdir("var/incoming");
    undo_swap_at_rename();
    clear_agentd_pidfiles();

    if (agt != NULL) {
        if (agt->server != NULL) {
            os_free(agt->server[0].rip);
            os_free(agt->server[0].endpoint);
            os_free(agt->server);
        }
        os_free(agt);
    }

    return 0;
}

/* --- the option table ----------------------------------------------------------------- */

static void test_parse_defaults(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", NULL};

    assert_int_equal(parse_argv(&opts, 1, argv, stderr), 0);
    assert_int_equal(opts.action, AGENT_AUTH_ACTION_ENROLL);
    assert_int_equal(opts.source, AGENT_AUTH_SOURCE_STDIN);
    assert_false(opts.force_enroll);
    assert_false(opts.certs_only);
    /* Pointing ossec.conf at the token's manager is what makes a move take effect, so it is on
     * unless the operator says otherwise. */
    assert_false(opts.certs_only);
}

/* The decision this whole binary is shaped around: a token must never be readable out of argv,
 * because ps and /proc expose it to every local user. --show-token is declared no_argument, so
 * an inline value is refused by getopt_long() and there is no code path that could read one. */
static void test_parse_show_token_rejects_an_inline_token(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", "--show-token=" TOKEN_PIN_ONLY, NULL};

    assert_int_equal(parse_argv(&opts, 2, argv, stderr), -2);
}

static void test_parse_show_token(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", "--show-token", NULL};

    assert_int_equal(parse_argv(&opts, 2, argv, stderr), 0);
    assert_int_equal(opts.action, AGENT_AUTH_ACTION_SHOW);
}

static void test_parse_token_file(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", "--token-file", "/root/tok", NULL};

    assert_int_equal(parse_argv(&opts, 3, argv, stderr), 0);
    assert_int_equal(opts.source, AGENT_AUTH_SOURCE_FILE);
    assert_string_equal(opts.token_file, "/root/tok");
}

static void test_parse_token_file_dash_is_stdin(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", "--token-file", "-", NULL};

    assert_int_equal(parse_argv(&opts, 3, argv, stderr), 0);
    assert_int_equal(opts.source, AGENT_AUTH_SOURCE_STDIN);
}

static void test_parse_certs_only_with_a_token_file(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", "--token-file", "/root/tok", "--certs-only", NULL};

    assert_int_equal(parse_argv(&opts, 4, argv, stderr), 0);
    assert_int_equal(opts.source, AGENT_AUTH_SOURCE_FILE);
    assert_string_equal(opts.token_file, "/root/tok");
    assert_true(opts.certs_only);
}

static void test_parse_guards_and_config_flag(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char *argv[] = {"wazuh-agent-auth", "--force-enroll", "--dry-run", NULL};

    assert_int_equal(parse_argv(&opts, 3, argv, stderr), 0);
    assert_true(opts.force_enroll);
    assert_true(opts.dry_run);
    assert_false(opts.certs_only);
}

/* --- --show-token ---------------------------------------------------------------------- */

static void test_show_token_renders_without_the_credential(void **state) {
    (void) state;
    char out_buf[4096] = {0};
    char err_buf[512] = {0};
    char token[] = TOKEN_WITH_KEY "\n";   /* a shell pipe appends the newline */
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    assert_int_equal(w_agent_show_token(in, out, err, "wazuh-agent-auth"), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "ver: 1\n"));
    assert_non_null(strstr(out_buf, "adr: new.example.local:1518\n"));
    assert_non_null(strstr(out_buf, "pin: " FROZEN_PIN_HEX "\n"));
    /* The token carries a credential, and the output must say so without ever carrying it. */
    assert_non_null(strstr(out_buf, "credential: present\n"));
    assert_null(strstr(out_buf, FROZEN_KEY_B64));
    assert_null(strstr(out_buf, FROZEN_ID_B64));
    assert_null(strstr(out_buf, "key"));
}

static void test_show_token_rejects_a_bad_token(void **state) {
    (void) state;
    char out_buf[512] = {0};
    char err_buf[512] = {0};
    char token[] = "not-a-token";
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    /* 2, not 1: register_configure_agent.sh tells a rejected token apart from a decoder it
     * never managed to run, which exits 127. */
    assert_int_equal(w_agent_show_token(in, out, err, "wazuh-agent-auth"), AGENT_AUTH_ERR_TOKEN);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_string_equal(out_buf, "");
    assert_non_null(strstr(err_buf, "invalid enrollment token"));
}

static void test_show_token_refuses_an_oversized_token(void **state) {
    (void) state;
    char out_buf[512] = {0};
    char err_buf[512] = {0};
    char *token = NULL;

    os_calloc(W_ETOKEN_MAX_FILE_BYTES + 64, sizeof(char), token);
    memset(token, 'A', W_ETOKEN_MAX_FILE_BYTES + 32);

    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    assert_int_equal(w_agent_show_token(in, out, err, "wazuh-agent-auth"), AGENT_AUTH_ERR_USAGE);

    fclose(in);
    fclose(out);
    fclose(err);
    os_free(token);

    assert_non_null(strstr(err_buf, "does not fit"));
}

/* --- the guards ------------------------------------------------------------------------ */

/* Replacing a registration is destructive and irreversible from the agent's side: the manager
 * mints a new id and the old registration is left behind. It must take an explicit --replace. */
static void test_enroll_refuses_when_already_registered(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_USAGE);

    fclose(in);
    fclose(out);
    fclose(err);

    /* Nothing was attempted, and the operator is told what --force-enroll would cost them. */
    assert_string_equal(out_buf, "");
    assert_non_null(strstr(err_buf, "already has a key"));
    assert_non_null(strstr(err_buf, "id=003"));
    assert_non_null(strstr(err_buf, "NEW id"));
    assert_non_null(strstr(err_buf, "--force-enroll"));
}


/* Replacing the anchor under a running agent is not a deferred inconvenience: the transport
 * reads the CA by path on every handshake, so the running agent starts verifying against the
 * new manager while still holding the old identity, and reaches neither until restarted. */
static void test_enroll_refuses_while_agentd_is_running(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    g_agentd_alive = true;
    seed_agentd_pidfile(FAKE_AGENTD_PID);
    w_agent_auth_opts_init(&opts);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_USAGE);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_string_equal(out_buf, "");
    /* No override to offer and no diagnosis to give: it names the one thing to do. */
    assert_non_null(strstr(err_buf, "stop the agent first"));
    assert_non_null(strstr(err_buf, "4711"));
    assert_non_null(strstr(err_buf, "wazuh-control stop"));
}

/* A pid file left behind by a crash must not look like a running agent, and must not be
 * deleted either: removing one is touching service state, which this command does not do. */
static void test_stale_pidfile_is_not_a_running_agent(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    char path[PATH_MAX];
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    g_agentd_alive = false;          /* kill(pid, 0) answers ESRCH */
    seed_agentd_pidfile(FAKE_AGENTD_PID);
    w_agent_auth_opts_init(&opts);
    opts.dry_run = true;             /* stop before anything is contacted */

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_null(strstr(err_buf, "wazuh-agentd is running"));

    snprintf(path, sizeof(path), "%s/wazuh-agentd-%d.pid", OS_PIDFILE, FAKE_AGENTD_PID);
    assert_int_equal(IsFile(path), 0);
}

/* --dry-run is the preflight: it must report the damage it would do and do none of it. */
static void test_dry_run_writes_nothing(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.force_enroll = true;
    opts.dry_run = true;

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    /* One stream for the whole preview: split between out and err it arrived out of order as
     * soon as stdout was redirected. */
    assert_non_null(strstr(out_buf, "would enroll with manager=siem.example.local"));
    assert_non_null(strstr(out_buf, "would REPLACE the registration id=003"));
    assert_non_null(strstr(out_buf, "nothing was contacted"));
    assert_string_equal(err_buf, "");

    /* Both halves of "writes nothing": the key it would have replaced is untouched, and the
     * anchor it would have installed was never created. */
    assert_int_equal(FileSize(KEYS_FILE), (int64_t) strlen(EXISTING_KEY_LINE));
    assert_int_equal(IsFile(AGENT_ANCHOR_CA), -1);
}


/* --- the four the plan named as carrying the decisions --------------------------------- */

/* The enrollment path logs through the wrapped debug_op family, and the exact sequence depends
 * on details these cases are not about (TempFile()'s benign FSTAT_ERROR, whether a placeholder
 * client.keys exists). These tests assert on the operator-facing stream instead, so any logging
 * is accepted -- unlike test_token_bootstrap.c, which pins the exact lines because the log IS
 * what it is testing. */
#define LOG_DEBUG1  0x01
#define LOG_INFO    0x02
#define LOG_ERROR   0x04

static void allow_any_logging(int which) {
    /* Registered per test rather than wholesale: cmocka reports an always-expectation that is
     * never consumed as a leftover, so declaring a wrapper this path does not reach fails the
     * test it was meant to unblock. */
    if (which & LOG_DEBUG1) {
        expect_any_always(__wrap__mdebug1, formatted_msg);
    }

    if (which & LOG_INFO) {
        expect_any_always(__wrap__minfo, formatted_msg);
    }

    if (which & LOG_ERROR) {
        expect_any_always(__wrap__merror, formatted_msg);
    }
}

/* Queues a successful enrollment: pin matches, manager answers 200 with a usable key line. */
static void expect_successful_enrollment(void) {
    will_return(__wrap_hc_spki_pinned_certificate, 1);
    will_return(__wrap_hc_enroll, 200);
    will_return(__wrap_hc_enroll,
                "{\"id\":\"007\",\"name\":\"e2e\",\"ip\":\"any\",\"key\":\"deadbeef\"}");
    will_return(__wrap_hc_enroll, 1);
}

/* The manager refuses an enrollment carrying a key_hash it recognises, so sending one would
 * defeat the very operation --replace asks for. The core never reads client.keys; this is what
 * holds that property in place. */
static void test_enroll_never_sends_key_hash(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);   /* a key IS present, the tempting case */
    w_agent_auth_opts_init(&opts);
    opts.force_enroll = true;
        allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    expect_successful_enrollment();

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_int_equal(g_enroll_calls, 1);
    assert_null(strstr(g_enroll_body, "key_hash"));
}

/* An operator's token file is theirs: it may be on read-only media, shared across a fleet, or
 * recorded in a runbook. Only the installer's own etc/enrollment_token is consumed. */
static void test_operator_token_file_is_never_removed(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file("operator-token", TOKEN_PIN_ONLY "\n");
    w_agent_auth_opts_init(&opts);
    opts.source = AGENT_AUTH_SOURCE_FILE;
    opts.token_file = "operator-token";
        allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    expect_successful_enrollment();

    assert_int_equal(w_agent_auth_run(&opts, stdin, out, err), AGENT_AUTH_OK);

    fclose(out);
    fclose(err);

    assert_int_equal(IsFile("operator-token"), 0);
    assert_int_equal(FileSize("operator-token"), (int64_t) strlen(TOKEN_PIN_ONLY) + 1);
    unlink("operator-token");
}

/* A refused enrollment must leave the agent exactly as it was -- this is what makes exit 4 safe
 * to retry, and what the "Nothing was changed." line promises. */
static void test_refused_enrollment_leaves_the_old_state(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    write_file(AGENT_ANCHOR_CA, "OLD-CA");
    w_agent_auth_opts_init(&opts);
    opts.force_enroll = true;

    allow_any_logging(LOG_INFO | LOG_ERROR);
    will_return(__wrap_hc_spki_pinned_certificate, 1);
    will_return(__wrap_hc_enroll, 401);
    will_return(__wrap_hc_enroll, "{\"error\":{\"code\":401,\"message\":\"denied\"}}");
    will_return(__wrap_hc_enroll, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_ENROLL);

    fclose(in);
    fclose(out);
    fclose(err);

    /* Byte-for-byte, not merely present. */
    assert_int_equal(FileSize(KEYS_FILE), (int64_t) strlen(EXISTING_KEY_LINE));
    assert_int_equal(FileSize(AGENT_ANCHOR_CA), (int64_t) strlen("OLD-CA"));
    assert_non_null(strstr(err_buf, "Nothing was changed"));
}

/* The Windows agent UI shows the manager's reason by finding this exact line on stderr, so a
 * refusal must carry it, prefix and text together. */
static void test_refused_enrollment_reports_the_manager_reason(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    write_file(AGENT_ANCHOR_CA, "OLD-CA");
    w_agent_auth_opts_init(&opts);
    opts.force_enroll = true;

    allow_any_logging(LOG_INFO | LOG_ERROR);
    will_return(__wrap_hc_spki_pinned_certificate, 1);
    will_return(__wrap_hc_enroll, 409);
    will_return(__wrap_hc_enroll, "{\"error\":{\"code\":9008,\"message\":\"Duplicate name\"}}");
    will_return(__wrap_hc_enroll, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_ENROLL);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(err_buf, "  " AGENT_AUTH_MANAGER_SAID "Duplicate name\n"));
    assert_string_equal(out_buf, "");
}

/* The config rewrite is the one step that reports success without the data changing:
 * OS_WriteXMLToStream returns 0 when the node is absent. Reading the value back is what tells the
 * two apart. */
static void test_config_rewrite_refuses_when_the_node_is_absent(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(WAZUHCONF, "<ossec_config><agent></agent></ossec_config>\n");

    /* No logging expectations: this path reaches neither the debug line TempFile() emits on a
     * missing source nor any info/error -- everything it reports goes to the caller's stream. */
    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local");
    /* What the rewritten file ends up containing: the node still absent. */
    will_return(__wrap_OS_WriteXMLToStream, "<ossec_config><agent></agent></ossec_config>\n");
    will_return(__wrap_OS_WriteXMLToStream, 0);          /* ...and OS_WriteXMLToStream still says success */

    assert_int_equal(w_agent_auth_update_endpoint("new.example.local", "old.example.local", err), -1);

    fclose(err);

    assert_non_null(strstr(err_buf, "has no <agent><manager><endpoint>"));
    /* The live file was left alone rather than replaced with an unchanged copy. */
    assert_non_null(strstr(err_buf, "left"));
}

static void assert_file_content(const char *path, const char *expected) {
    char buf[1024] = {0};
    FILE *fp = fopen(path, "r");

    assert_non_null(fp);
    assert_int_equal(fread(buf, 1, sizeof(buf) - 1, fp), strlen(expected));
    fclose(fp);
    assert_string_equal(buf, expected);
}

/* etc/ is writable by the account the agent runs as, and this command runs as root. If that
 * account swaps the staged copy for a symlink, nothing may be written through it, nor have its
 * mode or owner changed -- the target can be any file on the host. */
static void test_config_rewrite_never_follows_a_swapped_staging_file(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");
    struct stat target;

    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    write_file(SWAP_TARGET, SWAP_TARGET_CONTENT);
    assert_int_equal(chmod(SWAP_TARGET, 0600), 0);
    g_swap_staged = true;

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    will_return(__wrap_OS_WriteXMLToStream, REWRITTEN_CONFIG);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_update_endpoint("new.example.local:1518", "siem.example.local", err), -1);

    fclose(err);

    assert_file_content(SWAP_TARGET, SWAP_TARGET_CONTENT);
    assert_int_equal(stat(SWAP_TARGET, &target), 0);
    assert_int_equal(target.st_mode & 07777, 0600);
    /* chown() and fchown() are no-ops here, so who would have owned what is checked by name and
     * by inode instead: never by name, and never the target's inode. */
    assert_int_equal(g_chown_calls, 0);
    assert_int_not_equal(g_fchown_ino, target.st_ino);
    assert_file_content(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    assert_non_null(strstr(err_buf, "was replaced while it was being written"));
}

/* The rewritten file keeps the live one's mode and owner, and both are set through the staged
 * file's descriptor: by name, they land on whatever the name points at by then. */
static void test_config_rewrite_sets_mode_and_owner_through_the_descriptor(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");
    struct stat rewritten;

    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    assert_int_equal(chmod(WAZUHCONF, 0640), 0);

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    will_return(__wrap_OS_WriteXMLToStream, REWRITTEN_CONFIG);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_update_endpoint("new.example.local:1518", "siem.example.local", err), 0);

    fclose(err);

    assert_int_equal(g_chown_calls, 0);
    assert_int_equal(g_fchmodat_calls, 0);
    assert_int_equal(g_fchown_calls, 1);
    assert_int_equal(g_fchown_owner, getuid());
    assert_int_equal(g_fchown_group, getgid());
    assert_int_equal(stat(WAZUHCONF, &rewritten), 0);
    /* The owner went to the file that was installed, whichever call carried it there. */
    assert_int_equal(g_fchown_ino, rewritten.st_ino);
    assert_int_equal(rewritten.st_mode & 07777, 0640);
    assert_file_content(WAZUHCONF, REWRITTEN_CONFIG);
}

/* After every check on the staged copy has passed, the account that can write etc/ makes the move
 * fail and points ossec.conf at another file. The move has to fail as a move: copying into
 * ossec.conf by name instead would have root truncate that other file. */
static void test_config_rewrite_install_never_writes_through_a_symlink(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    write_file(SWAP_TARGET, SWAP_TARGET_CONTENT);
    g_swap_at_rename = true;

    /* Allowed, not required: only a fallback copy would log here. Optional, so that a regression
     * fails on the target below rather than on an unexpected log line. */
    expect_any_count(__wrap__mdebug1, formatted_msg, WILL_RETURN_ONCE);
    expect_any_count(__wrap__merror, formatted_msg, WILL_RETURN_ONCE);

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    will_return(__wrap_OS_WriteXMLToStream, REWRITTEN_CONFIG);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_update_endpoint("new.example.local:1518", "siem.example.local", err), -1);

    fclose(err);

    assert_false(g_swap_at_rename);
    assert_file_content(SWAP_TARGET, SWAP_TARGET_CONTENT);
    assert_non_null(strstr(err_buf, "could not install"));
}

/* The rewrite is read back to confirm the node changed. That read goes through the staged file's
 * descriptor, never its name, which can point anywhere by then. */
static void test_config_rewrite_reads_the_staged_copy_back_through_its_descriptor(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    will_return(__wrap_OS_WriteXMLToStream, REWRITTEN_CONFIG);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_update_endpoint("new.example.local:1518", "siem.example.local", err), 0);

    fclose(err);

    assert_int_equal(g_staged_reads_by_name, 0);
    assert_file_content(WAZUHCONF, REWRITTEN_CONFIG);
}

/* stdio can lose part of a write and still let the flush and the close after it succeed; only the
 * stream's error flag remembers. A rewrite with a hole in it is refused, not installed. */
static void test_config_rewrite_refuses_a_rewrite_that_lost_a_write(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    g_lose_staged_write = true;

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    will_return(__wrap_OS_WriteXMLToStream, REWRITTEN_CONFIG);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_update_endpoint("new.example.local:1518", "siem.example.local", err), -1);

    fclose(err);

    assert_file_content(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    assert_non_null(strstr(err_buf, "could not rewrite"));
}


/* --- the three agent states, and --certs-only ------------------------------------------ */

/* "Already registered" must mean what the first-boot latch means by it. A client.keys whose
 * first line carries no space -- a removed-agent marker, a comment, a half-written line -- is
 * still an enrolled agent, and must still take --force-enroll. */
static void test_registered_is_decided_by_content_not_by_shape(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, "!003\n");          /* no space: the old test said "not enrolled" */
    w_agent_auth_opts_init(&opts);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_USAGE);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_string_equal(out_buf, "");
    assert_non_null(strstr(err_buf, "already has a key"));
    assert_non_null(strstr(err_buf, "--force-enroll"));
    /* The id could not be parsed, so it is named as unknown rather than guessed at. */
    assert_non_null(strstr(err_buf, "id=unknown"));
}

/* A dry run writes and contacts nothing, so it must preview the operation rather than refuse
 * it -- being told to pass the flag you are deciding about is the wrong way round. */
static void test_dry_run_previews_instead_of_refusing(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.dry_run = true;                      /* deliberately WITHOUT --force-enroll */

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "would enroll with manager="));
    assert_non_null(strstr(out_buf, "would REPLACE the registration id=003"));
    assert_non_null(strstr(out_buf, "nothing was contacted"));
    assert_string_equal(err_buf, "");
    assert_int_equal(FileSize(KEYS_FILE), (int64_t) strlen(EXISTING_KEY_LINE));
}

/* --certs-only refreshes trust material, so an agent with no registration has nothing to
 * refresh and is pointed at the plain enroll instead. */
static void test_certs_only_refuses_when_not_enrolled(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_USAGE);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(err_buf, "not enrolled"));
    assert_non_null(strstr(err_buf, "without --certs-only"));
}

/* An enrolled agent refreshing its anchor needs no --force-enroll: the registration is not
 * touched, so asking permission for it would be noise. */
static void test_certs_only_needs_no_force_enroll(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "anchor installed manager="));
    /* The registration is exactly as it was, and nothing was enrolled. */
    assert_int_equal(FileSize(KEYS_FILE), (int64_t) strlen(EXISTING_KEY_LINE));
    assert_int_equal(g_enroll_calls, 0);
    assert_int_equal(FileSize(AGENT_ANCHOR_CA), (int64_t) strlen(PINNED_CERT));
    /* This token names the address already configured, so the rewrite is a no-op. Asserted
     * rather than left incidental: it is the other half of "only when it differs", and without
     * it no OS_WriteXMLToStream expectation is queued and the mock would have to be the one to complain. */
    assert_null(strstr(err_buf, "now points"));
}

/* Running it again with the same token must say so and write nothing, so the command is safe
 * in a configuration-management loop. */
static void test_certs_only_is_idempotent(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    write_file(AGENT_ANCHOR_CA, PINNED_CERT);   /* already exactly what the token pins */
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "anchor unchanged manager="));
    assert_int_equal(g_enroll_calls, 0);
    assert_null(strstr(err_buf, "now points"));
}

/* A CA a WPK upgrade staged but could not validate is superseded once --certs-only installs the
 * anchor; left behind, a later upgrade would install it over this one. */
static void test_certs_only_removes_a_ca_staged_by_an_upgrade(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    mkdir("var", 0755);
    mkdir("var/incoming", 0755);
    write_file(AGENT_DELIVERED_CA, "STALE-CA");
    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "anchor installed manager="));
    assert_int_equal(FileSize(AGENT_ANCHOR_CA), (int64_t) strlen(PINNED_CERT));
    assert_int_not_equal(IsFile(AGENT_DELIVERED_CA), 0);
}

/* Same when the anchor already holds this CA: nothing is rewritten, but the staged copy is
 * still stale. */
static void test_certs_only_unchanged_still_removes_a_staged_ca(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    mkdir("var", 0755);
    mkdir("var/incoming", 0755);
    write_file(AGENT_DELIVERED_CA, "STALE-CA");
    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    write_file(AGENT_ANCHOR_CA, PINNED_CERT);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    allow_any_logging(LOG_INFO);
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "anchor unchanged manager="));
    assert_int_not_equal(IsFile(AGENT_DELIVERED_CA), 0);
}

/* The preview has to cover what the run would do, and --certs-only now re-points the address
 * too. The line used to live in the enrolling arm only, so a --certs-only dry run previewed an
 * anchor write and silently omitted the config write it was about to make. */
static void test_certs_only_dry_run_previews_the_config_rewrite(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_WITH_KEY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    opts.dry_run = true;

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "would install anchor manager=new.example.local:1518"));
    assert_non_null(strstr(out_buf, "would point <manager><endpoint> at 'new.example.local:1518'"));
    assert_non_null(strstr(out_buf, "nothing was contacted"));
    assert_string_equal(err_buf, "");
    /* Contacted nothing: a preview must not reach the manager for the anchor either. */
    assert_int_equal(g_fetch_calls, 0);
}

/* The preview also names the staged CA the run would remove, and still touches nothing. */
static void test_certs_only_dry_run_previews_removing_a_staged_ca(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    mkdir("var", 0755);
    mkdir("var/incoming", 0755);
    write_file(AGENT_DELIVERED_CA, "STALE-CA");
    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    opts.dry_run = true;

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "would remove the CA a remote upgrade left at " AGENT_DELIVERED_CA));
    assert_int_equal(IsFile(AGENT_DELIVERED_CA), 0);
}

/* A staged CA that cannot be removed is reported, and the anchor install still succeeds. */
static void test_certs_only_warns_when_a_staged_ca_cannot_be_removed(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    mkdir("var", 0755);
    mkdir("var/incoming", 0755);
    /* A directory makes unlink() fail with something other than ENOENT. */
    mkdir(AGENT_DELIVERED_CA, 0755);
    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    expect_string(__wrap__mwarn, formatted_msg,
                  "Could not remove the CA a remote upgrade left at '" AGENT_DELIVERED_CA "': Is a "
                  "directory (21). Remove it, or a later upgrade may install it over the trust anchor.");
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "anchor installed manager="));
}

/* An ossec.conf with no <agent><manager> block at all parses fine and leaves the agent with no
 * address to dial. The rewrite cannot insert the node -- OS_WriteXMLToStream() appends it after
 * </ossec_config> and still reports success -- so the command has to say so rather than report a
 * move it did not make. Regression guard for a run that enrolled and exited 0 with the agent
 * still pointed nowhere. */
static void test_enroll_reports_a_config_with_no_manager_block(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    /* What ClientConf() leaves behind when <agent><manager> is absent: it returns 0. */
    os_free(agt->server[0].rip);
    agt->server[0].rip = NULL;

    w_agent_auth_opts_init(&opts);
    allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    expect_successful_enrollment();

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_CONFIG);

    fclose(in);
    fclose(out);
    fclose(err);

    /* The enrollment itself stands and is reported; only the pointer to it could not be written. */
    assert_non_null(strstr(out_buf, "enrolled id="));
    assert_non_null(strstr(err_buf, "has no <agent><manager><endpoint> to point"));
    assert_non_null(strstr(err_buf, "Add it by hand"));
}

/* A manager that changes its name almost always reissues its certificate at the same time, so
 * --certs-only is the mode an operator reaches for. It has to carry the address across too: the
 * outcome line names the address in the TOKEN, which would otherwise be one the agent never
 * dials. The registration stays untouched -- that is the whole distinction from enrolling. */
static void test_certs_only_points_the_config_at_the_new_address(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    /* Names new.example.local:1518, which is not setup_test()'s configured siem.example.local. */
    char token[] = TOKEN_WITH_KEY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    will_return(__wrap_OS_WriteXMLToStream, REWRITTEN_CONFIG);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(out_buf, "anchor installed manager="));
    assert_non_null(strstr(err_buf, "now points <manager><endpoint> at 'new.example.local:1518'"));
    /* Trust and address only. The identity is the one thing this mode must never touch. */
    assert_int_equal(FileSize(KEYS_FILE), (int64_t) strlen(EXISTING_KEY_LINE));
    assert_int_equal(g_enroll_calls, 0);
}

/* The anchor is installed and only the pointer to it failed, which is a different remediation
 * from a failed commit -- so it is a different exit code. Nothing asserted a 6 out of
 * w_agent_auth_run() before this, on either path. */
static void test_certs_only_reports_a_failed_config_rewrite(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_WITH_KEY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    write_file(KEYS_FILE, EXISTING_KEY_LINE);
    write_file(WAZUHCONF, CONFIG_WITH_ENDPOINT);
    w_agent_auth_opts_init(&opts);
    opts.certs_only = true;
    allow_any_logging(LOG_DEBUG1 | LOG_INFO);
    will_return(__wrap_hc_spki_pinned_certificate, 1);

    expect_string(__wrap_OS_WriteXMLToStream, newval, "new.example.local:1518");
    /* OS_WriteXMLToStream reports success having changed nothing -- the silent no-op the read-back
     * guard in w_agent_auth_update_endpoint() exists to catch. */
    will_return(__wrap_OS_WriteXMLToStream, CONFIG_WITH_ENDPOINT);
    will_return(__wrap_OS_WriteXMLToStream, 0);

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_CONFIG);

    fclose(in);
    fclose(out);
    fclose(err);

    /* The anchor still went in; the message must not leave that in doubt. */
    assert_non_null(strstr(out_buf, "anchor installed manager="));
    assert_non_null(strstr(err_buf, "The trust anchor is in place"));
    assert_non_null(strstr(err_buf, "by hand before restarting"));
}

/* A token typed as an operand is the one mistake whose error message must not quote its input:
 * the value is the credential, and stderr is read, scrolled back and captured. */
static void test_operand_is_refused_without_echoing_it(void **state) {
    (void) state;
    char err_buf[2048] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");
    char *argv[] = {"wazuh-agent-auth", TOKEN_PIN_ONLY, NULL};

    assert_int_equal(w_agent_auth_reject_operands(2, argv, 1, err), -1);

    fclose(err);

    assert_non_null(strstr(err_buf, "unexpected argument"));
    assert_non_null(strstr(err_buf, "--token-file"));
    /* The whole point. */
    assert_null(strstr(err_buf, TOKEN_PIN_ONLY));
}

/* Nothing left over is not an error. */
static void test_no_operand_is_accepted(void **state) {
    (void) state;
    char err_buf[256] = {0};
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");
    char *argv[] = {"wazuh-agent-auth", NULL};

    assert_int_equal(w_agent_auth_reject_operands(1, argv, 1, err), 0);

    fclose(err);
    assert_string_equal(err_buf, "");
}

/* A token file past the ceiling used to be read truncated by fgets() and then reported as
 * malformed, sending the operator to inspect a token that is merely too big. */
static void test_oversized_token_file_is_reported_as_too_big(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    FILE *in = fmemopen((char *) "", 0, "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");
    char *oversized;

    os_calloc(W_ETOKEN_MAX_FILE_BYTES + 64, sizeof(char), oversized);
    memset(oversized, 'A', W_ETOKEN_MAX_FILE_BYTES + 32);
    write_file("big-token", oversized);
    os_free(oversized);

    w_agent_auth_opts_init(&opts);
    opts.source = AGENT_AUTH_SOURCE_FILE;
    opts.token_file = "big-token";

    assert_int_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_ERR_USAGE);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(err_buf, "does not fit"));
    assert_null(strstr(err_buf, "malformed"));
}

/* An agent that has a trust anchor but an empty client.keys is the worst shape a failed commit
 * can leave behind: there is nothing to snapshot, so nothing is restored, and the warning used to
 * be gated on whether a key existed beforehand -- which is false in exactly this case. The
 * headline alone does not say the agent can now reach no manager at all. */
static void test_a_failed_commit_warns_even_with_no_previous_key(void **state) {
    (void) state;
    agent_auth_opts_t opts;
    char out_buf[1024] = {0};
    char err_buf[2048] = {0};
    char token[] = TOKEN_PIN_ONLY;
    FILE *in = fmemopen(token, strlen(token), "r");
    FILE *out = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err = fmemopen(err_buf, sizeof(err_buf), "w");

    /* An anchor with no key beside it: enough to enroll transactionally, nothing to roll back. */
    write_file(AGENT_ANCHOR_CA, "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n");

    w_agent_auth_opts_init(&opts);
    g_fail_anchor_move = true;
    allow_any_logging(LOG_DEBUG1 | LOG_INFO | LOG_ERROR);
    expect_successful_enrollment();

    assert_int_not_equal(w_agent_auth_run(&opts, in, out, err), AGENT_AUTH_OK);

    fclose(in);
    fclose(out);
    fclose(err);

    assert_non_null(strstr(err_buf, "can reach neither until it is re-enrolled"));
    /* There was no previous key, so the line about one not being restored must not appear. */
    assert_null(strstr(err_buf, "was NOT restored"));

    unlink(AGENT_ANCHOR_CA);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_parse_defaults, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_operand_is_refused_without_echoing_it, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_no_operand_is_accepted, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_oversized_token_file_is_reported_as_too_big, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_parse_show_token_rejects_an_inline_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_parse_show_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_parse_token_file, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_parse_token_file_dash_is_stdin, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_parse_certs_only_with_a_token_file, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_parse_guards_and_config_flag, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_show_token_renders_without_the_credential, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_show_token_rejects_a_bad_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_show_token_refuses_an_oversized_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_enroll_refuses_when_already_registered, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_enroll_refuses_while_agentd_is_running, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_stale_pidfile_is_not_a_running_agent, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_dry_run_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_enroll_never_sends_key_hash, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_operator_token_file_is_never_removed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_refused_enrollment_leaves_the_old_state, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_refused_enrollment_reports_the_manager_reason, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_rewrite_refuses_when_the_node_is_absent, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_rewrite_never_follows_a_swapped_staging_file, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_config_rewrite_sets_mode_and_owner_through_the_descriptor, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_config_rewrite_install_never_writes_through_a_symlink, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_config_rewrite_reads_the_staged_copy_back_through_its_descriptor,
                                        setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_rewrite_refuses_a_rewrite_that_lost_a_write, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_registered_is_decided_by_content_not_by_shape, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_dry_run_previews_instead_of_refusing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_refuses_when_not_enrolled, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_needs_no_force_enroll, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_is_idempotent, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_removes_a_ca_staged_by_an_upgrade, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_unchanged_still_removes_a_staged_ca, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_dry_run_previews_removing_a_staged_ca, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_warns_when_a_staged_ca_cannot_be_removed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_enroll_reports_a_config_with_no_manager_block, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_dry_run_previews_the_config_rewrite, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_points_the_config_at_the_new_address, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certs_only_reports_a_failed_config_rewrite, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_a_failed_commit_warns_even_with_no_previous_key, setup_test,
                                        teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

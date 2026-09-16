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
#include <sys/stat.h>

#include "shared.h"
#include "agentd.h"
#include "token_bootstrap.h"
#include "enrollment.h"
#include "enrollment_token.h"
#include "https_client.h"
#include "reenroll_secret.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

/* w_agent_token_bootstrap() runs end to end against real files relative to this binary's
 * working directory (same convention as test_client_conf_ssl_resolution.c): AGENT_ANCHOR_CA,
 * KEYS_FILE and AGENT_ENROLLMENT_TOKEN_FILE are all relative paths, so a real mkdir/fopen here
 * exercises the exact latch/read/write logic production code runs, with nothing to fake at
 * that layer. Only the https_client module boundary
 * (hc_fetch_cacerts/hc_enroll/hc_spki_pinned_certificate) is mocked, mirroring
 * test_https_client_bridge.c's own convention for that same boundary. */

/* Deliberately unlike the fetched body below: the anchor must end up holding the pinned
 * certificate alone, so the two have to be distinguishable. */
#define PINNED_CERT "PINNED-CERT-ONLY"

static hc_config_t g_fetch_config;
static int g_fetch_call_count = 0;

bool __wrap_hc_fetch_cacerts(const hc_config_t *config, const hc_cacerts_request_t *request,
                             hc_cacerts_result_t *result) {
    (void) request;
    g_fetch_call_count++;

    if (config) {
        g_fetch_config = *config;
    }

    if (result) {
        memset(result, 0, sizeof(*result));
        result->http_code = mock_type(long);
        const char *body = (const char *) mock();

        if (body != NULL) {
            strncpy(result->body, body, sizeof(result->body) - 1);
        }
    }

    return (bool) mock();
}

static hc_config_t g_enroll_config;
static hc_enroll_request_t g_enroll_request;
static int g_enroll_call_count = 0;

bool __wrap_hc_enroll(const hc_config_t *config, const hc_enroll_request_t *request,
                      hc_enroll_result_t *result) {
    g_enroll_call_count++;

    if (config) {
        g_enroll_config = *config;
    }

    if (request) {
        g_enroll_request = *request;
    }

    if (result) {
        memset(result, 0, sizeof(*result));
        result->http_code = mock_type(long);
        const char *body = (const char *) mock();

        if (body != NULL) {
            strncpy(result->body, body, sizeof(result->body) - 1);
        }
    }

    return (bool) mock();
}

static int g_spki_call_count = 0;

/* Returns the pinned certificate itself, not a verdict: what the bootstrap installs as the
 * anchor must be this certificate alone and never the bundle it was found in, so the tests
 * feed a value here that is deliberately different from the fetched body and then assert on
 * which of the two reached the anchor. A NULL means no certificate matched. */
bool __wrap_hc_spki_pinned_certificate(const char *cacerts_body, size_t body_len,
                                       const char *pin_b64url, char *matched_pem,
                                       size_t matched_pem_size) {
    (void) cacerts_body;
    (void) body_len;
    (void) pin_b64url;
    g_spki_call_count++;

    const char *pem = (const char *) mock();

    if (pem == NULL) {
        return false;
    }

    snprintf(matched_pem, matched_pem_size, "%s", pem);
    return true;
}

/* The bootstrap asks for an anchor owned by root, which an unprivileged process cannot do:
 * running these for real would pass under sudo and fail for everyone else. Wrapped so the
 * outcome is the same either way, and so the ownership the bootstrap asks for can be asserted
 * rather than assumed. The last call of each is recorded for that. */
static uid_t g_anchor_chown_uid = (uid_t) -1;
static gid_t g_anchor_chown_gid = (gid_t) -1;
static uid_t g_dir_chown_uid = (uid_t) -1;
static gid_t g_dir_chown_gid = (gid_t) -1;
static uid_t g_secret_chown_uid = (uid_t) -1;
static gid_t g_secret_chown_gid = (gid_t) -1;
static uid_t g_keys_chown_uid = (uid_t) -1;
static gid_t g_keys_chown_gid = (gid_t) -1;

/* The anchor's chown() target is the TempFile()-created temporary file
 * ("etc/certs/root-ca.pem.XXXXXX", a random mkstemp() suffix appended to the destination name --
 * see file_op.c), not the final AGENT_ANCHOR_CA path itself: the chown happens before the
 * rename, not after. A suffix match on "root-ca.pem" would miss that entirely, so this matches
 * on the basename *starting with* "root-ca.pem" instead, which catches both the temporary name
 * and the final one. */
static bool is_anchor_path(const char *path) {
    const char *prefix = "root-ca.pem";
    const char *base;

    if (!path) {
        return false;
    }

    base = strrchr(path, '/');
    base = base ? base + 1 : path;

    return strncmp(base, prefix, strlen(prefix)) == 0;
}

/* The anchor's parent directory (etc/certs), chowned separately from the anchor file itself --
 * see w_token_bootstrap_ensure_parent_dir() in token_bootstrap.c. */
static bool is_anchor_dir_path(const char *path) {
    return path && strcmp(path, "etc/certs") == 0;
}

/* The re-enrollment secret. Prefix-matched on the basename for the same reason as the anchor:
 * w_reenroll_secret_store() chmod()s TempFile()'s name, which appends to it, before renaming. */
static bool is_secret_path(const char *path) {
    const char *prefix = "reenroll.secret";
    const char *base;

    if (!path) {
        return false;
    }

    base = strrchr(path, '/');
    base = base ? base + 1 : path;

    return strncmp(base, prefix, strlen(prefix)) == 0;
}

/* The re-enrollment secret's own exact match, for the same reason as is_keys_file_path(): the
 * store is written through TempFile() too, so a prefix match would also accept
 * "etc/reenroll.secret.XXXXXX" and pass even if a refactor chowned the temp file instead of the
 * installed path. Distinct from is_secret_path() above, which is deliberately a prefix match
 * because the chmod it guards DOES land on the temp name. */
static bool is_secret_file_path(const char *path) {
    static const char suffix[] = "/reenroll.secret";
    size_t path_len = path ? strlen(path) : 0;

    return path_len >= sizeof(suffix) - 1 &&
           strcmp(path + path_len - (sizeof(suffix) - 1), suffix) == 0;
}

int __wrap_chown(const char *path, uid_t owner, gid_t group) {
    if (is_secret_file_path(path)) {
        /* Recorded on the PATH-based entry point as well as the fd-based one below, deliberately:
         * this is the call the hardening exists to remove, so a regression that goes back to
         * chown(path, ...) has to show up here rather than leave the fd recorder untouched and
         * the "was not chowned" assertion passing for the wrong reason. */
        g_secret_chown_uid = owner;
        g_secret_chown_gid = group;
    } else if (is_anchor_path(path)) {
        g_anchor_chown_uid = owner;
        g_anchor_chown_gid = group;
    } else if (is_anchor_dir_path(path)) {
        g_dir_chown_uid = owner;
        g_dir_chown_gid = group;
    }

    return 0;
}

/* client.keys is chowned via w_token_bootstrap_chown_keys_file() (token_bootstrap.c), which
 * opens it with O_NOFOLLOW and fchown()s the descriptor instead of calling chown() on the path
 * -- a symlink planted in etc/ (0770 root:wazuh, like the anchor's own 01770 root:gid
 * directory) must not make a root-privileged chown() follow it to an arbitrary target. The fd
 * is resolved back to a path via /proc/self/fd to keep matching this suite's existing
 * by-path convention. */
static bool g_keys_fchown_should_fail = false;

/* Exact match, not a substring one: a loose match (e.g. strstr() on "/client.keys") would also
 * match a hypothetical "etc/client.keys.XXXXXX" temp variant, silently passing even if a future
 * refactor mistakenly chowned the temp file instead of the installed path -- exactly the mistake
 * the sibling anchor guard (is_anchor_path() vs is_anchor_dir_path()) exists to catch. */
static bool is_keys_file_path(const char *path) {
    static const char suffix[] = "/client.keys";
    size_t path_len = path ? strlen(path) : 0;

    return path_len >= sizeof(suffix) - 1 &&
           strcmp(path + path_len - (sizeof(suffix) - 1), suffix) == 0;
}

int __wrap_fchown(int fd, uid_t owner, gid_t group) {
    char link[64];
    char path[PATH_MAX];
    ssize_t len;

    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    len = readlink(link, path, sizeof(path) - 1);

    if (len > 0) {
        path[len] = '\0';

        if (is_secret_file_path(path)) {
            g_secret_chown_uid = owner;
            g_secret_chown_gid = group;
        } else if (is_keys_file_path(path)) {
            if (g_keys_fchown_should_fail) {
                errno = EACCES;
                return -1;
            }

            g_keys_chown_uid = owner;
            g_keys_chown_gid = group;
        }
    }

    return 0;
}

/* Recorded now (rather than discarded): the mode is set on the anchor's temporary file and on
 * its parent directory, both before the rename gives the anchor its final name, so tests assert
 * against the last chmod() call recorded for each target rather than the final AGENT_ANCHOR_CA
 * path. Wrapped so an unprivileged run behaves like a privileged one either way. */
static mode_t g_dir_chmod_mode = (mode_t) -1;
static mode_t g_anchor_chmod_mode = (mode_t) -1;
static mode_t g_secret_chmod_mode = (mode_t) -1;

int __wrap_chmod(const char *path, mode_t mode) {
    if (is_anchor_dir_path(path)) {
        g_dir_chmod_mode = mode;
    } else if (is_anchor_path(path)) {
        g_anchor_chmod_mode = mode;
    } else if (is_secret_path(path)) {
        g_secret_chmod_mode = mode;
    }

    return 0;
}

/* Regression guard: the anchor's chown() must land on the temporary file before OS_MoveFile()
 * renames it into place, never after. __real_OS_MoveFile() (resolved by the linker's --wrap
 * because this test binary is not itself the true entry point) preserves the real rename so the
 * rest of the suite keeps exercising a real file on disk. */
extern int __real_OS_MoveFile(const char *src, const char *dst);
static bool g_anchor_chown_recorded_before_move = false;

/* Set by the rollback tests: the anchor's rename is the last step of the commit, and making it
 * fail is the only way to reach the path where an enrollment has already replaced client.keys. */
static bool g_fail_anchor_move = false;

int __wrap_OS_MoveFile(const char *src, const char *dst) {
    if (is_anchor_path(src) && g_anchor_chown_uid != (uid_t) -1) {
        g_anchor_chown_recorded_before_move = true;
    }

    if (g_fail_anchor_move && is_anchor_path(src)) {
        return -1;
    }

    return __real_OS_MoveFile(src, dst);
}

/* ---- fixtures ---- */

/* Removes every "<name>.XXXXXX" TempFile() staged beside @p path. A failed commit leaves one
 * behind by design in some paths, and without this they accumulate across runs of this binary
 * and make any "nothing was left behind" assertion count the previous run's litter. */
static void remove_staged_siblings(const char *dir, const char *prefix) {
    char **entries = wreaddir(dir);

    if (entries == NULL) {
        return;
    }

    for (int i = 0; entries[i] != NULL; i++) {
        char path[PATH_MAX];

        if (strncmp(entries[i], prefix, strlen(prefix)) == 0 &&
                strlen(entries[i]) > strlen(prefix)) {
            snprintf(path, sizeof(path), "%s/%s", dir, entries[i]);
            unlink(path);
        }
    }

    free_strarray(entries);
}

static void remove_test_paths(void) {
    unlink("etc/enrollment_token");
    unlink("etc/certs/root-ca.pem");
    /* Must be cleared with the anchor: w_token_bootstrap_mark_anchor_committed() is a no-op when
     * one already exists, so a marker left behind by an earlier test would make every later
     * assertion about it pass without anything having written one. */
    unlink("etc/certs/.anchor-committed");
    unlink("etc/client.keys");
    unlink("etc/other-file");
    unlink(AGENT_REENROLL_SECRET);
    remove_staged_siblings("etc/certs", "root-ca.pem.");
    remove_staged_siblings("etc", "client.keys.");
}

static int group_setup(void **state) {
    (void) state;
    mkdir("etc", 0755);
    mkdir("etc/certs", 0755);
    remove_test_paths();
    return 0;
}

static int setup_test(void **state) {
    (void) state;
    remove_test_paths();

    agt = (agent *) calloc(1, sizeof(agent));
    os_strdup("test-agent", agt->enrollment.agent_name);
    memset(&keys, 0, sizeof(keys));

    memset(&g_fetch_config, 0, sizeof(g_fetch_config));
    memset(&g_enroll_config, 0, sizeof(g_enroll_config));
    memset(&g_enroll_request, 0, sizeof(g_enroll_request));
    g_fetch_call_count = 0;
    g_enroll_call_count = 0;
    g_fail_anchor_move = false;
    g_spki_call_count = 0;
    g_anchor_chown_uid = (uid_t) -1;
    g_anchor_chown_gid = (gid_t) -1;
    g_dir_chown_uid = (uid_t) -1;
    g_dir_chown_gid = (gid_t) -1;
    g_secret_chown_uid = (uid_t) -1;
    g_secret_chown_gid = (gid_t) -1;
    g_keys_chown_uid = (uid_t) -1;
    g_keys_chown_gid = (gid_t) -1;
    g_keys_fchown_should_fail = false;
    g_dir_chmod_mode = (mode_t) -1;
    g_anchor_chmod_mode = (mode_t) -1;
    g_secret_chmod_mode = (mode_t) -1;
    g_anchor_chown_recorded_before_move = false;

    return 0;
}

static int teardown_test(void **state) {
    (void) state;

    if (agt) {
        os_free(agt->enrollment.agent_name);
        os_free(agt->enrollment.groups);
        os_free(agt->enrollment.agent_address);
        os_free(agt->enrollment.authorization_pass_path);
        free(agt);
        agt = NULL;
    }

    if (keys.keyentries) {
        if (keys.keyentries[0]) {
            os_free(keys.keyentries[0]->id);
            os_free(keys.keyentries[0]->name);
            os_free(keys.keyentries[0]->raw_key);
            os_free(keys.keyentries[0]);
        }

        os_free(keys.keyentries);
    }

    remove_test_paths();
    return 0;
}

static void write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static char *read_file(const char *path) {
    static char buf[256];
    memset(buf, 0, sizeof(buf));
    FILE *fp = fopen(path, "r");
    assert_non_null(fp);
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    (void) n;
    fclose(fp);
    return buf;
}

/* Builds and writes a real token, through the production encoder, so the decoder this module
 * runs against is exercised with exactly the wire format authd itself mints -- no hand-crafted
 * base64/JSON in this file. */
/* The encoded token, for tests that call w_agent_token_enroll() directly rather than going
 * through the latched wrapper. Caller frees. */
static char *make_token(bool has_pin, bool has_key, const char *ca_pem) {
    w_etoken_t token;
    memset(&token, 0, sizeof(token));
    token.ver = 1;
    token.adr = "127.0.0.1:1517/wazuh-manager";

    if (has_pin) {
        token.has_pin = 1;
        memset(token.pin, 0xAB, sizeof(token.pin));
    } else {
        token.ca_pem = (char *) ca_pem;
    }

    if (has_key) {
        token.has_key = 1;
        memset(token.id, 0x01, sizeof(token.id));
        memset(token.secret, 0x02, sizeof(token.secret));
    }

    char *encoded = w_etoken_encode(&token);
    assert_non_null(encoded);
    return encoded;
}

static void write_token_file(bool has_pin, bool has_key, const char *ca_pem) {
    w_etoken_t token;
    memset(&token, 0, sizeof(token));
    token.ver = 1;
    token.adr = "127.0.0.1:1517/wazuh-manager";

    if (has_pin) {
        token.has_pin = 1;
        memset(token.pin, 0xAB, sizeof(token.pin));
    } else {
        token.ca_pem = (char *) ca_pem;
    }

    if (has_key) {
        token.has_key = 1;
        memset(token.id, 0x01, sizeof(token.id));
        memset(token.secret, 0x02, sizeof(token.secret));
    }

    char *encoded = w_etoken_encode(&token);
    assert_non_null(encoded);
    write_file("etc/enrollment_token", encoded);
    free(encoded);
}

/* w_enrollment_process_response()'s own OS_IsValidIP(ip, NULL) call must be mocked here (same
 * convention test_enrollment.c already follows): real PCRE2 matching is not safe/deterministic
 * to run unmocked under this test's ASan build. */
static void expect_valid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

#define VALID_ENROLL_BODY \
    "{\"id\":\"001\",\"name\":\"test-agent\",\"ip\":\"10.0.0.5\"," \
    "\"key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"

/* The same 200, with the fifth field a 5.0 manager actually sends (#39064). */
#define REENROLL_SECRET "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define VALID_ENROLL_BODY_WITH_SECRET \
    "{\"id\":\"001\",\"name\":\"test-agent\",\"ip\":\"10.0.0.5\"," \
    "\"key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"," \
    "\"reenroll_secret\":\"" REENROLL_SECRET "\"}"

/* ---- tests ---- */

/* w_enrollment_build_request() announces the identity it is about to present before it picks a
 * credential (#38678, merged from 5.0.0), so it is the first minfo() any test that reaches it sees.
 * Declared once here rather than repeated literally: what these tests assert is the credential
 * choice that follows, and this line is only in the way of it. */
#define expect_enrolling_as_line() \
    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.")

static void test_no_token_file_is_noop(void **state) {
    (void) state;

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_anchor_already_present_skips_and_discards_the_token(void **state) {
    (void) state;
    write_file("etc/certs/root-ca.pem", "EXISTING-ANCHOR");
    write_file("etc/client.keys", "001 test-agent 10.0.0.5 aaaa\n");
    write_token_file(true, true, NULL);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    /* Nothing is fetched or enrolled, and the anchor already in place is untouched -- but the
     * token is removed all the same. It is one-shot, this agent is past the point of using it,
     * and leaving it would keep a credential on disk that nothing will ever consume. */
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);
    assert_string_equal(read_file("etc/certs/root-ca.pem"), "EXISTING-ANCHOR");

    /* Regression guard: this is the only latch a crash between the anchor's rename and
     * client.keys's own chown (see w_agent_token_bootstrap()'s final chown) can ever reach
     * again -- once the anchor exists, every later boot returns here, never falling through to
     * the "already enrolled" branch below. It must repair client.keys's group every time it
     * fires, not just skip out, or that crash leaves client.keys root:root permanently. */
    assert_int_equal(g_keys_chown_uid, 0);
    assert_int_equal(g_keys_chown_gid, getgid());
}

static void test_already_enrolled_skips_and_discards_the_token(void **state) {
    (void) state;
    write_file("etc/client.keys", "001 test-agent 10.0.0.5 aaaa\n");
    write_token_file(true, true, NULL);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    /* Same reasoning as the anchor latch above: an agent that already holds a key will never
     * spend this token, so it does not stay on disk. */
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    /* Regression guard: this latch must still repair client.keys's group every time it fires,
     * not just skip out -- a prior boot's enrollment call can replace client.keys (via
     * TempFile()+OS_MoveFile() in enrollment.c) and die before the chown below ever runs,
     * leaving it root:root until a later boot passes through here again. */
    assert_int_equal(g_keys_chown_uid, 0);
    assert_int_equal(g_keys_chown_gid, getgid());
}

/* Regression test: a hard link is a regular file by every other measure -- O_NOFOLLOW does not
 * stop it, only its link count gives it away. etc/ is 0770 root:wazuh, so the runtime user could
 * otherwise hard-link some other root-owned file to client.keys's path and have this
 * root-privileged repair fchown() it to root:wazuh instead. */
static void test_client_keys_hard_link_is_not_chowned(void **state) {
    (void) state;
    write_file("etc/other-file", "not-client-keys\n");
    assert_int_equal(link("etc/other-file", "etc/client.keys"), 0);
    write_token_file(true, true, NULL);

    /* This repair runs on every boot for as long as no anchor exists, so its failure is logged
     * at debug level rather than merror() -- see w_token_bootstrap_chown_keys_file()'s own
     * comment. */
    expect_any(__wrap__mdebug1, formatted_msg);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_equal(g_keys_chown_uid, (uid_t) -1);
    assert_int_equal(g_keys_chown_gid, (gid_t) -1);
}

/* Regression test: a failing fchown() on client.keys must be logged, not silently swallowed --
 * neither of the new ownership-repair branches this PR adds was previously exercised with a
 * failing chown, so a broken log call site there would have gone unnoticed. */
static void test_keys_chown_failure_is_logged(void **state) {
    (void) state;
    write_file("etc/client.keys", "001 test-agent 10.0.0.5 aaaa\n");
    write_token_file(true, true, NULL);
    g_keys_fchown_should_fail = true;

    /* This repair runs on every boot for as long as no anchor exists, so its failure is logged
     * at debug level rather than merror() -- see w_token_bootstrap_chown_keys_file()'s own
     * comment. */
    expect_any(__wrap__mdebug1, formatted_msg);

    /* The failure is logged, but does not fail the bootstrap itself: the token is one-shot and
     * this agent is already enrolled, so there is nothing left to retry here besides the chown
     * -- and that keeps getting retried on every later boot regardless. */
    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_equal(g_keys_chown_uid, (uid_t) -1);
    assert_int_equal(g_keys_chown_gid, (gid_t) -1);
}

/* Regression test: the anchor-latch branch runs on every single boot for as long as no anchor
 * has ever been removed, so a persistent chown failure there (e.g. a namespaced container
 * without CAP_CHOWN) must not re-log at merror() level on every boot -- that would flood the
 * log forever for a condition that will not self-resolve. */
static void test_anchor_latch_keys_chown_failure_is_quiet(void **state) {
    (void) state;
    write_file("etc/certs/root-ca.pem", "EXISTING-ANCHOR");
    write_file("etc/client.keys", "001 test-agent 10.0.0.5 aaaa\n");
    write_token_file(true, true, NULL);
    g_keys_fchown_should_fail = true;

    expect_any(__wrap__mdebug1, formatted_msg);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_keys_chown_uid, (uid_t) -1);
    assert_int_equal(g_keys_chown_gid, (gid_t) -1);
}

/* An agent that bootstrapped before #39321 holds a root-owned anchor under a 0750 directory, so
 * it could never adopt a published CA bundle: the refresh runs unprivileged and would fail at
 * mkstemp() every time, which reads as a manager problem rather than a local one. The latch --
 * the only branch an already-bootstrapped agent reaches -- repairs it on the next boot, while
 * still root, so an upgrade fixes itself with no operator action. */
static void test_anchor_latch_repairs_pre_39321_ownership(void **state) {
    (void) state;
    write_file("etc/certs/root-ca.pem", "EXISTING-ANCHOR");
    write_file("etc/client.keys", "001 test-agent 10.0.0.5 aaaa\n");
    write_token_file(true, true, NULL);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);

    /* The latch still holds: repairing permissions is not an excuse to re-fetch anything. */
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);

    /* The anchor moves to the runtime user, because the sticky bit below lets only the owner
     * rename over it. */
    assert_int_equal(g_anchor_chown_uid, getuid());
    assert_int_equal(g_anchor_chown_gid, getgid());

    /* The directory stays root-owned and gains group write plus the sticky bit. */
    assert_int_equal(g_dir_chown_uid, 0);
    assert_int_equal(g_dir_chown_gid, getgid());
    assert_int_equal(g_dir_chmod_mode, 01770);

    /* The marker is minted here too: an install from before #39321 has an anchor but no marker,
     * and without one the deletion guard could never fire for it. */
    assert_int_equal(IsFile("etc/certs/.anchor-committed"), 0);
}

/* Regression test: client.keys can exist as an empty 0-byte placeholder (the package's own
 * conffile default) that no prior test here modeled -- every existing test either unlinked
 * the file or wrote a real, non-empty entry. */
static void test_empty_placeholder_keys_file_is_not_already_enrolled(void **state) {
    (void) state;
    write_file("etc/client.keys", "");
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Only AGENT_ANCHOR_CA hits TempFile()'s benign FSTAT_ERROR mdebug1 here -- KEYS_FILE
     * already exists (the placeholder), so fstat() on it succeeds and that debug line
     * doesn't fire twice. */
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.");
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 1);
    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
}

static void test_malformed_token_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_file("etc/enrollment_token", "not-a-valid-token!!!");

    expect_string(__wrap__merror, formatted_msg,
                  "Could not decode the enrollment token: malformed token.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_PERMANENT);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_fetch_adr_unreachable_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 0L);
    will_return(__wrap_hc_fetch_cacerts, NULL);
    will_return(__wrap_hc_fetch_cacerts, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "/cacerts adr_unreachable -- could not reach the manager to "
                  "fetch the certificate authority.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_TRANSIENT);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_fetch_not_found_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 404L);
    will_return(__wrap_hc_fetch_cacerts, NULL);
    will_return(__wrap_hc_fetch_cacerts, 1);

    expect_string(__wrap__merror, formatted_msg,
                  "/cacerts not_found -- the manager has no certificate "
                  "authority configured (it may predate this feature).");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_PERMANENT);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_fetch_ca_mismatch_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 503L);
    will_return(__wrap_hc_fetch_cacerts, NULL);
    will_return(__wrap_hc_fetch_cacerts, 1);

    expect_string(__wrap__merror, formatted_msg,
                  "/cacerts ca_mismatch -- the manager's configured certificate "
                  "authority does not sign its own listener certificate (misprovisioned, not "
                  "necessarily hostile).");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_TRANSIENT);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_pin_mismatch_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, NULL);

    expect_string(__wrap__merror, formatted_msg,
                  "pin_mismatch -- fetched CA does not match the enrollment "
                  "token's pin, refusing to trust it.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_PERMANENT);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

/* #39064: a 403 carrying 9022/9023/9024 is authd's verdict on a token whose signature the manager
 * already verified -- unknown, revoked, or out of uses. Nothing else on this path clears the token:
 * the anchor is never installed and client.keys is never written, so neither latch trips next boot,
 * and the caller turns the -1 into merror_exit(). Keeping it would hand the same dead credential to
 * the same refusal on every restart -- the retry loop this issue exists to end, measured in process
 * lifetimes instead of HTTP attempts. */
static void test_fatal_token_refusal_discards_the_dead_token(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 403L);
    will_return(__wrap_hc_enroll, "{\"error\":{\"code\":9022,\"message\":\"revoked\"}}");
    will_return(__wrap_hc_enroll, 1);

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_enrolling_as_line();
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_PERMANENT);
    assert_int_equal(g_enroll_call_count, 1);

    /* The point of the test. */
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    /* Nothing was committed: the next boot takes the "no token provided" path, not this one. */
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

/* The other 403: enrollment administratively disabled, which carries no authd code and is
 * W_ENROLL_ERR_DISABLED rather than fatal. An operator can re-enable it, so the one-shot token must
 * survive -- discarding it here would need a newly minted token to undo a condition that clears
 * itself. This is the case that makes the fix a check on the STATUS and not on the 403. */
static void test_disabled_enrollment_keeps_the_token(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 403L);
    will_return(__wrap_hc_enroll, "{\"error\":{\"message\":\"disabled\"}}");
    will_return(__wrap_hc_enroll, 1);

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_enrolling_as_line();
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), W_TOKEN_BOOTSTRAP_PERMANENT);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/enrollment_token"), 0);
}

static void test_full_happy_path_via_pin(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* TempFile() logs a benign FSTAT_ERROR mdebug1 when the file it's about to replace doesn't
     * already exist (true for both AGENT_ANCHOR_CA and KEYS_FILE here); not asserted on exact
     * wording since errno text is platform-specific. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.");
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    /* The pinned certificate alone, not the bundle it arrived in: anything else in that body
     * was chosen by whoever answered an unverified fetch, and installing it would hand them a
     * trust anchor beside the genuine one. */
    assert_string_equal(read_file("etc/certs/root-ca.pem"), PINNED_CERT);
    assert_int_equal(IsFile("etc/client.keys"), 0);
    /* The one-shot token is discarded on success. */
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    /* And the marker is laid down beside the anchor, so a later boot can tell "this agent has
     * never held an anchor" from "this agent has lost the one it had". */
    assert_int_equal(IsFile("etc/certs/.anchor-committed"), 0);

    assert_int_equal(g_enroll_config.verify_mode, HC_VERIFY_FULL);
    assert_true(strlen(g_enroll_config.ca_path) > 0);
    assert_string_equal(g_enroll_request.password, "");
    assert_int_equal((int) strlen(g_enroll_request.enroll_kid), 22);
    assert_int_equal((int) strlen(g_enroll_request.enroll_key_hex), 64);
    /* Content, not just length: the manager verifies the bearer against a key it derives itself, so
     * an encoder that emitted the right number of wrong characters -- uppercase, most plausibly --
     * would fail authentication in the field while passing a length check here. */
    assert_int_equal((int) strspn(g_enroll_request.enroll_key_hex, "0123456789abcdef"), 64);

    /* The anchor is handed to the runtime user, not to root: under the sticky etc/certs only the
     * owner may rename over a file, so a root-owned anchor is one the agent could never replace
     * when the manager publishes a new CA bundle (#39321). The mode below is still 0640. */
    assert_int_equal(g_anchor_chown_uid, getuid());
    assert_int_equal(g_anchor_chown_gid, getgid());

    /* Regression guard: the anchor's chown() must land before OS_MoveFile() renames the temp
     * file into place, closing the window where a crash between the two left a wrong-group
     * AGENT_ANCHOR_CA permanently latching the bootstrap off. */
    assert_true(g_anchor_chown_recorded_before_move);

    /* Both the anchor and its parent directory get their mode fixed up while still root. The
     * directory is 01770, not 0750: group write is what rename(2) needs to replace the anchor
     * (it never consults the target file's own mode), and the sticky bit keeps that from
     * reaching anything root-owned that shares the directory. */
    assert_int_equal(g_anchor_chmod_mode, 0640);
    assert_int_equal(g_dir_chmod_mode, 01770);

    /* The parent directory itself stays root-owned: only its group gains write. */
    assert_int_equal(g_dir_chown_uid, 0);
    assert_int_equal(g_dir_chown_gid, getgid());

    /* client.keys is handed to root:gid too -- not uid:gid -- restoring the group that
     * enrollment.c's own TempFile()+OS_MoveFile() replace just dropped, without handing
     * ownership to the runtime user. */
    assert_int_equal(g_keys_chown_uid, 0);
    assert_int_equal(g_keys_chown_gid, getgid());
}

/* Regression test: unlike the two repair call sites (quiet_on_failure=true, covered above), the
 * fresh-enrollment call site (quiet_on_failure=false) must log at merror() level -- it runs once
 * per enrollment, not once per boot, so a failure there is a new, one-time event worth surfacing
 * loudly rather than folded into debug output. */
static void test_fresh_enrollment_keys_chown_failure_logs_merror(void **state) {
    (void) state;
    write_token_file(true, true, NULL);
    g_keys_fchown_should_fail = true;

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Same benign TempFile() FSTAT_ERROR mdebug1 as the happy-path tests, once for
     * AGENT_ANCHOR_CA and once for KEYS_FILE. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.");
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");
    expect_any(__wrap__merror, formatted_msg);

    /* The chown failure is logged but does not fail the bootstrap: enrollment itself already
     * succeeded, and the anchor-latch branch will keep retrying this same chown on every later
     * boot regardless. */
    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_keys_chown_uid, (uid_t) -1);
    assert_int_equal(g_keys_chown_gid, (gid_t) -1);
}

/* #39028's DoD: "a credential-less token enrolls when the simulator requires no credential,
 * and is not treated as an error." has_key=false must not short-circuit into an error path --
 * enrollment still runs, just with no enroll_kid/enroll_key_hex on the wire (and no fallback to
 * a configured password either, per token_bootstrap.c's own comment on that branch --
 * g_enroll_request.password stays empty exactly as it does on the keyed happy path). */
static void test_credential_less_token_enrolls_without_error(void **state) {
    (void) state;
    write_token_file(true, false, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Same benign TempFile() FSTAT_ERROR mdebug1 as the other happy-path tests, once for
     * AGENT_ANCHOR_CA and once for KEYS_FILE. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.");
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    /* The pinned certificate alone, not the bundle it arrived in: anything else in that body
     * was chosen by whoever answered an unverified fetch, and installing it would hand them a
     * trust anchor beside the genuine one. */
    assert_string_equal(read_file("etc/certs/root-ca.pem"), PINNED_CERT);
    assert_int_equal(IsFile("etc/client.keys"), 0);
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    assert_int_equal(g_enroll_config.verify_mode, HC_VERIFY_FULL);
    assert_true(strlen(g_enroll_config.ca_path) > 0);
    /* No key on the token: no kid, no derived key, and no fallback to a configured password
     * either -- the request goes out with no credential at all (see the comment next to this
     * branch in token_bootstrap.c). */
    assert_string_equal(g_enroll_request.password, "");
    assert_int_equal((int) strlen(g_enroll_request.enroll_kid), 0);
    assert_int_equal((int) strlen(g_enroll_request.enroll_key_hex), 0);
}

/* The bound has to clear what authd is willing to mint, not what a pin-only token happens to
 * need. A six-certificate bundle -- the largest #39321 lets a manager publish -- embeds to
 * roughly 9 KB of token, so at the old 8192 it minted cleanly and was then refused at the
 * agent's first boot, with nothing at install time having warned about it. */
static void test_embedded_ca_token_larger_than_the_old_cap_is_read(void **state) {
    (void) state;

    /* ~12 KB of body: past the old 8192 once base64url'd, far inside the new bound. */
    char big_ca[12288];
    memset(big_ca, 'A', sizeof(big_ca) - 1);
    big_ca[sizeof(big_ca) - 1] = '\0';

    write_token_file(false, true, big_ca);
    /* The guard this test exists for: the encoded token really is past the old limit. */
    assert_true(FileSize("etc/enrollment_token") > 8192);

    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.");
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_enroll_call_count, 1);

    /* The whole embedded bundle reached disk, not a truncated prefix of it. */
    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_equal(FileSize("etc/certs/root-ca.pem"), (long) strlen(big_ca));
}

static void test_full_happy_path_via_ca_pem(void **state) {
    (void) state;
    write_token_file(false, true, "FAKE-EMBEDDED-CA");

    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Same benign TempFile() FSTAT_ERROR mdebug1 as the pin-path test above, once for
     * AGENT_ANCHOR_CA and once for KEYS_FILE. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "Enrolling as 'test-agent'. Groups: none.");
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    /* No network fetch, no pin-compare: the CA was already embedded in the token. */
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_spki_call_count, 0);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_string_equal(read_file("etc/certs/root-ca.pem"), "FAKE-EMBEDDED-CA");
    assert_int_equal(IsFile("etc/client.keys"), 0);
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    /* Same regression guards as the pin-path happy test: the anchor's chown() must land before
     * the rename that installs it, and client.keys goes to root:gid. */
    assert_true(g_anchor_chown_recorded_before_move);
    assert_int_equal(g_keys_chown_uid, 0);
    assert_int_equal(g_keys_chown_gid, getgid());
}

/* #39064: the bootstrap runs as ROOT, before the privilege drop, and w_enrollment_process_response()
 * writes the re-enrollment secret from here. So the secret is created by a root-owned process and
 * then has to be handed to the unprivileged user like the anchor and client.keys are -- and unlike
 * those two it must end up WRITABLE by that user, because every later rotation happens in the
 * running daemon. A root-owned secret would survive exactly one enrollment and then fail every
 * rotation silently, which is the same shape of defect 65215f70bf had to fix for client.keys.
 *
 * chown() to the caller's own uid/gid is a no-op here (the suite does not run as root), so what
 * this pins is that the store is written on the root path, with client.keys's mode, and that no
 * ownership error is logged along the way -- an unexpected merror() would fail the test on the
 * strict cmocka log expectations. */
static void test_bootstrap_stores_the_reenroll_secret_from_the_root_path(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];
    struct stat info;

    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY_WITH_SECRET);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* One more TempFile() FSTAT_ERROR debug line than the happy path above (the secret is written
     * through one too), plus w_reenroll_secret_store()'s own confirmation. Declared uninteresting
     * rather than counted: the count is not what this test is about. */
    expect_any_always(__wrap__mdebug1, formatted_msg);

    expect_enrolling_as_line();
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(id, "001");
    assert_string_equal(secret, REENROLL_SECRET);

    /* client.keys's mode, so the daemon can rewrite it after the drop. Read off the wrapper
     * rather than stat(): __wrap_chmod() records the mode instead of applying it, so the file on
     * disk keeps mkstemp()'s 0600 and only the recorded value shows what the code asked for. */
    assert_int_equal(stat(AGENT_REENROLL_SECRET, &info), 0);
    assert_int_equal(g_secret_chmod_mode, 0640);

    /* And handed to the runtime user, not left root-owned: unlike client.keys (root:gid) the
     * daemon has to WRITE this one after the privilege drop. Recorded off __wrap_fchown(), which
     * also proves the chown went through the vetted descriptor rather than the path. */
    assert_int_equal(g_secret_chown_uid, getuid());
    assert_int_equal(g_secret_chown_gid, getgid());
}

/* The re-enrollment secret shares client.keys's 0770 root:wazuh directory, so the same link swap
 * applies -- and lands harder, because this chown names the unprivileged user as the OWNER rather
 * than only its group: following a planted link would hand that user outright ownership of
 * whatever it points at. A linked path must be refused, not followed.
 *
 * Driven with a manager response that carries no secret, so the link planted below is still in
 * place when the chown runs: a response WITH a secret would have TempFile()+OS_MoveFile() replace
 * the link with a real file first, which is the very thing that makes the real-world window a
 * race rather than a standing hole. */
static void test_reenroll_secret_link_is_not_chowned(void **state) {
    (void) state;
    /* A *valid* store ("<id> <secret>\n", see w_reenroll_secret_store()), not arbitrary bytes:
     * the bootstrap reads the existing store on its way through, and junk here would log a
     * "malformed" merror of its own and blur what this test is actually pinning. */
    write_file("etc/other-file", "001 " REENROLL_SECRET "\n");
    assert_int_equal(link("etc/other-file", AGENT_REENROLL_SECRET), 0);
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    expect_any_always(__wrap__mdebug1, formatted_msg);

    /* A valid store on disk means w_enrollment_build_request() prefers it over every other
     * credential (#39064), so this is the re-enrollment path, not the password one. */
    expect_enrolling_as_line();
    expect_string(__wrap__minfo, formatted_msg,
                  "Re-enrolling with this agent's own re-enrollment secret.");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");
    /* The refusal is reported and the bootstrap still succeeds -- enrollment already happened,
     * same disposition as client.keys's own chown failure. EMLINK is what w_openat_nofollow_vetted()
     * returns for a hard-linked path. */
    expect_string(__wrap__merror, formatted_msg,
                  "Could not change ownership of 'etc/reenroll.secret': "
                  "Too many links (31).");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);

    /* Nothing was chowned: the vetted open refused the link before fchown() was reached. */
    assert_int_equal(g_secret_chown_uid, (uid_t) -1);
    assert_int_equal(g_secret_chown_gid, (gid_t) -1);
}

/* A manager that sends no secret must still complete the bootstrap: the token path predates this
 * field and an older manager is not an error. */
static void test_bootstrap_without_a_secret_leaves_no_store(void **state) {
    (void) state;

    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_enrolling_as_line();
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(IsFile("etc/client.keys"), 0);
    assert_int_not_equal(IsFile(AGENT_REENROLL_SECRET), 0);
}


/* --- the transaction ------------------------------------------------------------------
 *
 * These drive w_agent_token_enroll() directly: the latched wrapper always passes
 * transactional=false, because a first boot has nothing to roll back to, so nothing that goes
 * through w_agent_token_bootstrap() can reach this code at all. It is the mechanism the PR's
 * evidence cites for "commit fails -> previous identity restored byte for byte", and until now
 * no test touched it. */

#define PREVIOUS_KEY_LINE "007 old-agent any 1111111111111111111111111111111111111111111111111111111111111111\n"

/* The enrollment reaches the manager and client.keys is replaced; then the anchor's rename --
 * the last step of the commit -- fails. Without the rollback the agent is left holding the new
 * manager's key against the old manager's anchor, able to verify neither. */
static void test_failed_commit_restores_the_previous_key(void **state) {
    (void) state;
    w_token_enroll_opts_t opts = {0};
    w_token_enroll_report_t report;
    char *token = make_token(true, true, NULL);

    write_file(KEYS_FILE, PREVIOUS_KEY_LINE);
    write_file(AGENT_ANCHOR_CA, "OLD-CA");

    opts.token_text = token;
    opts.uid = -1;
    opts.gid = -1;
    opts.transactional = true;

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");
    /* The messages themselves are asserted by the tests above; here the subject is the on-disk
     * outcome, so any logging is allowed rather than restated. No mdebug1: both files already
     * exist here, so TempFile() never emits its FSTAT_ERROR line, and cmocka counts an
     * always-expectation that is never consumed as a leftover. */
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);

    g_fail_anchor_move = true;

    assert_int_equal(w_agent_token_enroll(&opts, &report), W_TOKEN_ENROLL_ERR_COMMIT);

    /* The whole point: byte for byte, not merely present. */
    assert_string_equal(read_file(KEYS_FILE), PREVIOUS_KEY_LINE);
    assert_true(report.rolled_back);
    /* Empty means the backup was consumed by a successful restore; a path here would mean the
     * operator has to put it back by hand. */
    assert_string_equal(report.keys_backup, "");

    free(token);
}

/* No backup is taken when there was nothing to save, and the report says so rather than claiming
 * a rollback that never happened. */
static void test_failed_commit_without_a_previous_key_reports_no_rollback(void **state) {
    (void) state;
    w_token_enroll_opts_t opts = {0};
    w_token_enroll_report_t report;
    char *token = make_token(true, true, NULL);

    opts.token_text = token;
    opts.uid = -1;
    opts.gid = -1;
    opts.transactional = true;   /* asked for, but there is no key and no anchor to snapshot */

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");
    /* The messages themselves are asserted by the tests above; here the subject is the
     * on-disk outcome, so any logging is allowed rather than restated. */
    expect_any_always(__wrap__mdebug1, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);

    g_fail_anchor_move = true;

    assert_int_equal(w_agent_token_enroll(&opts, &report), W_TOKEN_ENROLL_ERR_COMMIT);
    assert_false(report.rolled_back);

    free(token);
}

/* The staged anchor holds the new CA. Every other failure branch removes it; this one used to
 * free the name and leave the file, so a repeatedly failing commit littered the certs directory. */
static void test_failed_commit_leaves_no_staged_anchor(void **state) {
    (void) state;
    w_token_enroll_opts_t opts = {0};
    w_token_enroll_report_t report;
    char *token = make_token(true, true, NULL);
    char **leftovers;
    int staged = 0;

    write_file(KEYS_FILE, PREVIOUS_KEY_LINE);

    opts.token_text = token;
    opts.uid = -1;
    opts.gid = -1;
    opts.transactional = true;

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");
    /* The messages themselves are asserted by the tests above; here the subject is the
     * on-disk outcome, so any logging is allowed rather than restated. */
    expect_any_always(__wrap__mdebug1, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);

    g_fail_anchor_move = true;


    assert_int_equal(w_agent_token_enroll(&opts, &report), W_TOKEN_ENROLL_ERR_COMMIT);

    leftovers = wreaddir("etc/certs");

    if (leftovers != NULL) {
        for (int i = 0; leftovers[i] != NULL; i++) {
            if (strncmp(leftovers[i], "root-ca.pem.", 12) == 0) {
                staged++;
            }
        }
        free_strarray(leftovers);
    }

    assert_int_equal(staged, 0);

    free(token);
}

/* A token longer than the reader's buffer used to come back silently cut short, and the caller
 * then refused it as malformed -- which points whoever reads that message at the token's contents
 * instead of its size. Refusing it outright is what lets both callers say so. */
static void test_a_token_too_long_to_fit_is_refused_rather_than_truncated(void **state) {
    (void) state;

    char *oversized;
    os_calloc(W_ETOKEN_MAX_FILE_BYTES + 64, sizeof(char), oversized);
    memset(oversized, 'A', W_ETOKEN_MAX_FILE_BYTES + 32);
    write_file("etc/enrollment_token", oversized);
    os_free(oversized);

    char *token = w_agent_token_read_file("etc/enrollment_token");

    assert_null(token);
}

/* The boundary the guard above is measured against: a line that fills the buffer exactly, with
 * nothing after it, is not truncated and must be returned whole. The reader used to hand back
 * W_ETOKEN_MAX_FILE_BYTES - 2 characters here, quietly dropping the last one. */
static void test_a_token_that_fills_the_buffer_exactly_is_read_whole(void **state) {
    (void) state;

    const size_t longest = W_ETOKEN_MAX_FILE_BYTES - 1;
    char *exact;

    os_calloc(longest + 1, sizeof(char), exact);
    memset(exact, 'A', longest);
    write_file("etc/enrollment_token", exact);

    char *token = w_agent_token_read_file("etc/enrollment_token");

    assert_non_null(token);
    assert_int_equal(strlen(token), longest);
    assert_string_equal(token, exact);

    os_free(exact);
    os_free(token);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_no_token_file_is_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_anchor_already_present_skips_and_discards_the_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_already_enrolled_skips_and_discards_the_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_client_keys_hard_link_is_not_chowned, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_keys_chown_failure_is_logged, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_anchor_latch_keys_chown_failure_is_quiet, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_anchor_latch_repairs_pre_39321_ownership, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_empty_placeholder_keys_file_is_not_already_enrolled, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_malformed_token_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_fetch_adr_unreachable_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_fetch_not_found_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_fetch_ca_mismatch_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_pin_mismatch_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_fatal_token_refusal_discards_the_dead_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_disabled_enrollment_keeps_the_token, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_full_happy_path_via_pin, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_failed_commit_restores_the_previous_key, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_failed_commit_without_a_previous_key_reports_no_rollback, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_failed_commit_leaves_no_staged_anchor, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_fresh_enrollment_keys_chown_failure_logs_merror, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_credential_less_token_enrolls_without_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_full_happy_path_via_ca_pem, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_bootstrap_stores_the_reenroll_secret_from_the_root_path, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_bootstrap_without_a_secret_leaves_no_store, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_secret_link_is_not_chowned, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_a_token_too_long_to_fit_is_refused_rather_than_truncated, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_a_token_that_fills_the_buffer_exactly_is_read_whole, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_embedded_ca_token_larger_than_the_old_cap_is_read, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}

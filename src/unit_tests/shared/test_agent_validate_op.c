/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* OS_AddNewAgent()'s key generation and OS_IsValidAgentKey(): the agent key is exactly 32 CSPRNG
 * bytes stored as 64 lowercase hex chars (the HS256 secret of remoted's wazuh-agent+jwt profile). */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "shared.h"
#include "sec.h"
#include "agent_validate_op.h"
#include "../wrappers/externals/openssl/rand_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

static keystore keys;

static int setup_keys(void **state) {
    (void) state;
    memset(&keys, 0, sizeof(keys));
    OS_PassEmptyKeyfile();
    keys.keytree_id = rbtree_init();
    keys.keytree_ip = rbtree_init();
    keys.keytree_sock = rbtree_init();
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    return 0;
}

static int teardown_keys(void **state) {
    (void) state;
    OS_FreeKeys(&keys);
    return 0;
}

/* OS_AddKey() validates the ip column through OS_IsValidIP(), which is mocked in libwazuh_test: one
 * expectation per entry that actually reaches OS_AddKey(). -1 = "any". */
static void expect_add_key_ip_check(void) {
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
}

static int is_lower_hex_64(const char *s) {
    size_t i;
    if (!s || strlen(s) != 64) {
        return 0;
    }
    for (i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* --- generation ------------------------------------------------------------------------------ */

static void test_add_new_agent_generates_a_64_hex_key(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */
    expect_add_key_ip_check();

    int index = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->id, "001");
    assert_true(is_lower_hex_64(keys.keyentries[index]->raw_key));
    assert_true(OS_IsValidAgentKey(keys.keyentries[index]->raw_key));
}

static void test_two_generated_keys_differ(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 1);
    will_return(__wrap_RAND_bytes, 1);
    expect_add_key_ip_check();
    expect_add_key_ip_check();

    int a = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    int b = OS_AddNewAgent(&keys, NULL, "agent2", "any", NULL, 0);
    assert_true(a >= 0 && b >= 0);
    assert_string_not_equal(keys.keyentries[a]->raw_key, keys.keyentries[b]->raw_key);
    assert_int_equal(keys.keysize, 2);
}

static void test_csprng_failure_adds_nothing_and_reports_error(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 0); /* do not pass through... */
    will_return(__wrap_RAND_bytes, 0); /* ...and report failure */
    expect_string(__wrap__merror, formatted_msg,
                  "Unable to generate a key for agent 'agent1': the CSPRNG (RAND_bytes) failed.");

    int index = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    assert_int_equal(index, OS_INVALID);
    assert_int_equal(keys.keysize, 0);
}

static void test_explicit_key_is_stored_verbatim(void **state) {
    (void) state;
    const char *key = "0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff";

    /* No RAND_bytes call when the caller supplies the key. */
    expect_add_key_ip_check();
    int index = OS_AddNewAgent(&keys, "007", "agent7", "any", key, 0);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->id, "007");
    assert_string_equal(keys.keyentries[index]->raw_key, key);
}

static void test_agent_limit_is_checked_before_generating(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 1);
    expect_add_key_ip_check();
    assert_true(OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0) >= 0);

    /* max_agents = 1 with one agent already present: refused without touching the CSPRNG. */
    assert_int_equal(OS_AddNewAgent(&keys, NULL, "agent2", "any", NULL, 1), OS_ADDAGENT_LIMIT_REACHED);
}

static void test_id_counter_at_int_max_fails_instead_of_wrapping(void **state) {
    (void) state;
    keys.id_counter = INT_MAX;

    /* Refused before the CSPRNG or OS_AddKey are ever reached: no will_return()/expect_*() set up
     * for them, so cmocka fails the test if either gets called. */
    int index = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    assert_int_equal(index, OS_ADDAGENT_LIMIT_REACHED);
    assert_int_equal(keys.keysize, 0);
    assert_int_equal(keys.id_counter, INT_MAX);
}

/* --- OS_IsValidAgentInsertID --------------------------------------------------------------------- */

static void test_valid_agent_insert_id_accepts_the_full_int32_range(void **state) {
    (void) state;
    assert_true(OS_IsValidAgentInsertID("1"));
    assert_true(OS_IsValidAgentInsertID("003"));
    assert_true(OS_IsValidAgentInsertID("99999999")); /* past OS_IsValidID()'s unrelated 8-char cap */
    assert_true(OS_IsValidAgentInsertID("2147483647")); /* INT32_MAX */
}

static void test_valid_agent_insert_id_rejects_out_of_range_or_reserved(void **state) {
    (void) state;
    assert_false(OS_IsValidAgentInsertID(NULL));
    assert_false(OS_IsValidAgentInsertID(""));
    assert_false(OS_IsValidAgentInsertID("abc"));
    assert_false(OS_IsValidAgentInsertID("-5"));
    assert_false(OS_IsValidAgentInsertID("1.5"));
    assert_false(OS_IsValidAgentInsertID("0")); /* reserved for the manager */
    assert_false(OS_IsValidAgentInsertID("000"));
    assert_false(OS_IsValidAgentInsertID("2147483648")); /* INT32_MAX + 1 */
    assert_false(OS_IsValidAgentInsertID("4294967296")); /* 2^32: wraps to 0 pre-fix */
    assert_false(OS_IsValidAgentInsertID("10000000000"));
    assert_false(OS_IsValidAgentInsertID("1000000000000000000"));
    /* Long enough to overflow even strtol()'s 64-bit long: must not be misread as in range. */
    assert_false(OS_IsValidAgentInsertID("999999999999999999999999999999999999999999"));
}

/* --- OS_CanonicalAgentInsertID ------------------------------------------------------------------ */

static void test_canonical_agent_insert_id_is_one_spelling_per_number(void **state) {
    (void) state;
    char out[12];

    assert_int_equal(OS_CanonicalAgentInsertID("1", out, sizeof(out)), 0);
    assert_string_equal(out, "001");
    assert_int_equal(OS_CanonicalAgentInsertID("001", out, sizeof(out)), 0);
    assert_string_equal(out, "001");
    assert_int_equal(OS_CanonicalAgentInsertID("0001", out, sizeof(out)), 0); /* the alias it closes */
    assert_string_equal(out, "001");
    assert_int_equal(OS_CanonicalAgentInsertID("01000", out, sizeof(out)), 0);
    assert_string_equal(out, "1000");
    assert_int_equal(OS_CanonicalAgentInsertID("2147483647", out, sizeof(out)), 0);
    assert_string_equal(out, "2147483647");
}

static void test_canonical_agent_insert_id_rejects_what_insert_rejects(void **state) {
    (void) state;
    char out[12] = "untouched";

    assert_int_equal(OS_CanonicalAgentInsertID(NULL, out, sizeof(out)), -1);
    assert_int_equal(OS_CanonicalAgentInsertID("0", out, sizeof(out)), -1);
    assert_int_equal(OS_CanonicalAgentInsertID("0001x", out, sizeof(out)), -1);
    assert_int_equal(OS_CanonicalAgentInsertID("2147483648", out, sizeof(out)), -1);
    assert_int_equal(OS_CanonicalAgentInsertID("4294967297", out, sizeof(out)), -1);
    assert_int_equal(OS_CanonicalAgentInsertID("1", NULL, sizeof(out)), -1);
    assert_int_equal(OS_CanonicalAgentInsertID("2147483647", out, 4), -1); /* does not fit */
}

/* --- OS_IsValidAgentKey ------------------------------------------------------------------------ */

static void test_valid_agent_key_accepts_exactly_64_lowercase_hex(void **state) {
    (void) state;
    assert_true(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff"));
    assert_true(OS_IsValidAgentKey("0000000000000000000000000000000000000000000000000000000000000000"));
    assert_true(OS_IsValidAgentKey("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
}

static void test_valid_agent_key_rejects_other_shapes(void **state) {
    (void) state;
    assert_false(OS_IsValidAgentKey(NULL));
    assert_false(OS_IsValidAgentKey(""));
    /* 32 hex chars: 16 bytes, half the required key. */
    assert_false(OS_IsValidAgentKey("2b7e151628aed2a6abf7158809cf4f3c"));
    /* 48 hex chars: 24 bytes. */
    assert_false(OS_IsValidAgentKey("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6"));
    /* 63 and 65 chars. */
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61f"));
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff0"));
    /* Uppercase, non-hex, whitespace. */
    assert_false(OS_IsValidAgentKey("0030557A9FC4E90E33587DA2C7EC11365B80A5CAEF14395E83A8CDF2173C61FF"));
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61fg"));
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61f "));
    /* The API's alphanumeric shape that is not hex. */
    assert_false(OS_IsValidAgentKey("asdfASD0101asdfASD0101asdfASD0101asdfASD0101asdfASD0101asdfASD01"));
}

/* --- re-enrollment secret (#38993) --------------------------------------------------------- */

static void test_new_reenroll_secret_is_64_lowercase_hex_and_fresh(void **state) {
    (void) state;
    char a[AGENT_REENROLL_SECRET_HEX_CHARS + 1] = {0};
    char b[AGENT_REENROLL_SECRET_HEX_CHARS + 1] = {0};
    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */
    will_return(__wrap_RAND_bytes, 1);

    assert_int_equal(OS_NewReenrollSecret(a, sizeof(a)), 0);
    assert_int_equal(OS_NewReenrollSecret(b, sizeof(b)), 0);
    assert_true(is_lower_hex_64(a));
    assert_true(is_lower_hex_64(b));
    assert_true(OS_IsValidReenrollSecret(a));
    assert_string_not_equal(a, b);

    /* A short buffer is refused before the CSPRNG is even consulted; a CSPRNG failure leaves it empty. */
    char tiny[8] = "xx";
    assert_int_equal(OS_NewReenrollSecret(tiny, sizeof(tiny)), -1);
    assert_int_equal(OS_NewReenrollSecret(NULL, 0), -1);
    will_return(__wrap_RAND_bytes, 0);
    will_return(__wrap_RAND_bytes, 0);
    expect_string(__wrap__merror, formatted_msg, "Unable to generate a re-enrollment secret: the CSPRNG (RAND_bytes) failed.");
    assert_int_equal(OS_NewReenrollSecret(a, sizeof(a)), -1);
    assert_string_equal(a, "");
}

// OS_NewAgentKey() is the generator behind OS_AddNewAgent()'s NULL key, exposed for authd's re-enrollment
// (#38993), which needs the key BEFORE touching the keystore. Same shape, same refusal rules as the secret.
static void test_new_agent_key_is_64_lowercase_hex_and_fresh(void **state) {
    (void) state;
    char a[AGENT_KEY_HEX_CHARS + 1] = {0};
    char b[AGENT_KEY_HEX_CHARS + 1] = {0};
    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */
    will_return(__wrap_RAND_bytes, 1);

    assert_int_equal(OS_NewAgentKey(a, sizeof(a)), 0);
    assert_int_equal(OS_NewAgentKey(b, sizeof(b)), 0);
    assert_true(is_lower_hex_64(a));
    assert_true(is_lower_hex_64(b));
    assert_true(OS_IsValidAgentKey(a));
    assert_string_not_equal(a, b);

    /* A short buffer is refused before the CSPRNG is consulted; a CSPRNG failure leaves it empty and logs
     * nothing here -- OS_AddNewAgent() (and authd) name the agent in their own message. */
    char tiny[8] = "xx";
    assert_int_equal(OS_NewAgentKey(tiny, sizeof(tiny)), -1);
    assert_int_equal(OS_NewAgentKey(NULL, 0), -1);
    will_return(__wrap_RAND_bytes, 0);
    will_return(__wrap_RAND_bytes, 0);
    assert_int_equal(OS_NewAgentKey(a, sizeof(a)), -1);
    assert_string_equal(a, "");
}

static void test_valid_reenroll_secret_accepts_and_rejects_shapes(void **state) {
    (void) state;
    assert_true(OS_IsValidReenrollSecret("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    assert_false(OS_IsValidReenrollSecret(NULL));
    assert_false(OS_IsValidReenrollSecret(""));
    assert_false(OS_IsValidReenrollSecret("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"));   /* 63 */
    assert_false(OS_IsValidReenrollSecret("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")); /* 65 */
    assert_false(OS_IsValidReenrollSecret("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"));  /* upper */
    assert_false(OS_IsValidReenrollSecret("0123456789abcdeg0123456789abcdef0123456789abcdef0123456789abcdef"));  /* g */
}

#ifndef TEST_WINAGENT
/* OS_MoveFile() reaches the real one unless a test makes it fail. */
static bool g_fail_move = false;

int __real_OS_MoveFile(const char *src, const char *dst);

int __wrap_OS_MoveFile(const char *src, const char *dst) {
    if (g_fail_move) {
        return -1;
    }

    return __real_OS_MoveFile(src, dst);
}

/* TempFile() reaches the real one unless a test needs every write to the staged copy to fail, as
 * on a full disk: its stream is then pointed at /dev/full, and the file stays where it was made. */
static bool g_staged_disk_full = false;

int __real_TempFile(File *file, const char *source, int copy);

int __wrap_TempFile(File *file, const char *source, int copy) {
    int result = __real_TempFile(file, source, copy);

    if (result == 0 && g_staged_disk_full) {
        fclose(file->fp);
        file->fp = fopen("/dev/full", "w");
        assert_non_null(file->fp);
    }

    return result;
}

#define TIMESTAMPS "001 web-01 any 2026-10-07 10:00:00\n" \
                   "002 db-01 any 2026-10-07 10:00:01\n" \
                   "003 mail-01 any 2026-10-07 10:00:02\n"

static void write_timestamps(const char *content) {
    FILE *fp;

    mkdir("queue", 0750);
    fp = fopen(TIMESTAMP_FILE, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static void assert_timestamps(const char *expected) {
    char buf[512] = {0};
    FILE *fp = fopen(TIMESTAMP_FILE, "r");

    assert_non_null(fp);
    assert_true(fread(buf, 1, sizeof(buf) - 1, fp) > 0);
    fclose(fp);
    assert_string_equal(buf, expected);
}

/* TempFile() stages the rewrite beside TIMESTAMP_FILE, as "<name>.XXXXXX". */
static bool is_staged_timestamp_file(const char *name) {
    return strncmp(name, "agents-timestamp.", 17) == 0;
}

static int count_staged_timestamp_files(void) {
    DIR *dir = opendir("queue");
    struct dirent *entry;
    int staged = 0;

    assert_non_null(dir);

    while ((entry = readdir(dir)) != NULL) {
        if (is_staged_timestamp_file(entry->d_name)) {
            staged++;
        }
    }

    closedir(dir);
    return staged;
}

/* A run that failed before cleaning up leaves its staged copies in queue/, and the next run would
 * count them as its own. */
static void remove_staged_timestamp_files(void) {
    char path[PATH_MAX];
    DIR *dir = opendir("queue");
    struct dirent *entry;

    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (is_staged_timestamp_file(entry->d_name)) {
            snprintf(path, sizeof(path), "queue/%s", entry->d_name);
            unlink(path);
        }
    }

    closedir(dir);
}

static int setup_timestamps(void **state) {
    (void) state;
    remove_staged_timestamp_files();
    return 0;
}

static int teardown_timestamps(void **state) {
    (void) state;
    g_fail_move = false;
    g_staged_disk_full = false;
    unlink(TIMESTAMP_FILE);
    rmdir(TIMESTAMP_FILE);
    remove_staged_timestamp_files();
    return 0;
}

static void test_remove_agent_timestamp_drops_only_that_agent(void **state) {
    (void) state;
    write_timestamps(TIMESTAMPS);

    OS_RemoveAgentTimestamp("002");

    assert_timestamps("001 web-01 any 2026-10-07 10:00:00\n003 mail-01 any 2026-10-07 10:00:02\n");
    assert_int_equal(count_staged_timestamp_files(), 0);
}

/* When the staged copy can't be moved into place, the timestamps stay as they were and the copy
 * is removed rather than left in queue/, one more for every agent removed. */
static void test_remove_agent_timestamp_cleans_up_after_a_failed_move(void **state) {
    (void) state;
    write_timestamps(TIMESTAMPS);
    g_fail_move = true;

    OS_RemoveAgentTimestamp("002");

    assert_timestamps(TIMESTAMPS);
    assert_int_equal(count_staged_timestamp_files(), 0);
}

#ifdef __linux__
/* A rewrite that couldn't be written in full is never moved into place: it would replace every
 * remaining agent's timestamp with whatever made it to disk. */
static void test_remove_agent_timestamp_keeps_the_file_when_the_rewrite_fails(void **state) {
    (void) state;
    write_timestamps(TIMESTAMPS);
    g_staged_disk_full = true;

    expect_string(__wrap__merror, formatted_msg,
                  "(1110): Could not write file 'queue/agents-timestamp' due to [(28)-(No space left on device)].");

    OS_RemoveAgentTimestamp("002");

    assert_timestamps(TIMESTAMPS);
    assert_int_equal(count_staged_timestamp_files(), 0);
}
#endif

/* Nor is a copy of a file that couldn't be read through. A directory where the file should be
 * stands in for a read error: it opens, and every read from it fails. */
static void test_remove_agent_timestamp_keeps_the_file_when_it_cannot_be_read(void **state) {
    struct stat st;

    (void) state;
    mkdir("queue", 0750);
    assert_int_equal(mkdir(TIMESTAMP_FILE, 0750), 0);

    expect_string(__wrap__merror, formatted_msg,
                  "(1115): Could not read from file 'queue/agents-timestamp' due to [(21)-(Is a directory)].");

    OS_RemoveAgentTimestamp("002");

    assert_int_equal(stat(TIMESTAMP_FILE, &st), 0);
    assert_true(S_ISDIR(st.st_mode));
    assert_int_equal(count_staged_timestamp_files(), 0);
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_add_new_agent_generates_a_64_hex_key, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_two_generated_keys_differ, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_csprng_failure_adds_nothing_and_reports_error, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_explicit_key_is_stored_verbatim, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_agent_limit_is_checked_before_generating, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_id_counter_at_int_max_fails_instead_of_wrapping, setup_keys, teardown_keys),
        cmocka_unit_test(test_valid_agent_insert_id_accepts_the_full_int32_range),
        cmocka_unit_test(test_valid_agent_insert_id_rejects_out_of_range_or_reserved),
        cmocka_unit_test(test_canonical_agent_insert_id_is_one_spelling_per_number),
        cmocka_unit_test(test_canonical_agent_insert_id_rejects_what_insert_rejects),
        cmocka_unit_test(test_valid_agent_key_accepts_exactly_64_lowercase_hex),
        cmocka_unit_test(test_valid_agent_key_rejects_other_shapes),
        cmocka_unit_test(test_new_reenroll_secret_is_64_lowercase_hex_and_fresh),
        cmocka_unit_test(test_new_agent_key_is_64_lowercase_hex_and_fresh),
        cmocka_unit_test(test_valid_reenroll_secret_accepts_and_rejects_shapes),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_remove_agent_timestamp_drops_only_that_agent, setup_timestamps,
                                        teardown_timestamps),
        cmocka_unit_test_setup_teardown(test_remove_agent_timestamp_cleans_up_after_a_failed_move, setup_timestamps,
                                        teardown_timestamps),
#ifdef __linux__
        cmocka_unit_test_setup_teardown(test_remove_agent_timestamp_keeps_the_file_when_the_rewrite_fails,
                                        setup_timestamps, teardown_timestamps),
#endif
        cmocka_unit_test_setup_teardown(test_remove_agent_timestamp_keeps_the_file_when_it_cannot_be_read,
                                        setup_timestamps, teardown_timestamps),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The identity transition journal: queue/authd/pending-identities, and the three questions it
 * answers -- may this transition be performed at all, what is still owed to the database, and what
 * does a line left by a dead process mean now (issue #39078, H03).
 *
 * Real files in a temporary directory, like the token store's cases and for the same reason: the
 * file IS the contract. Its mode, the fact that an append never rewrites it, and what a torn line
 * does to the next start are the properties being fixed here, and stubbing the I/O away would
 * leave nothing but the linked list.
 *
 * The log functions are wrapped, so each case declares the severities its own paths emit; an
 * undeclared line aborts cmocka from inside the journal's mutex, which hangs the run rather than
 * failing it.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "auth.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define JOURNAL_PATH "queue/authd/pending-identities"

#define KEY_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define KEY_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SECRET_A "1111111111111111111111111111111111111111111111111111111111111111"
#define SECRET_B "2222222222222222222222222222222222222222222222222222222222222222"

static char test_cwd[PATH_MAX];
static char test_dir[PATH_MAX];

#define EXPECT_LOG_INFO()  expect_any_always(__wrap__minfo, formatted_msg)
#define EXPECT_LOG_WARN()  expect_any_always(__wrap__mwarn, formatted_msg)
#define EXPECT_LOG_ERROR() expect_any_always(__wrap__merror, formatted_msg)

/* --- Fixtures ---------------------------------------------------------------------------------- */

static int setup_group(void **state) {
    (void)state;

    assert_non_null(getcwd(test_cwd, sizeof(test_cwd)));

    snprintf(test_dir, sizeof(test_dir), "/tmp/wazuh_identity_XXXXXX");
    assert_non_null(mkdtemp(test_dir));
    assert_int_equal(chdir(test_dir), 0);
    assert_int_equal(mkdir("queue", 0770), 0);
    assert_int_equal(mkdir("queue/authd", 0750), 0);

    return 0;
}

static int teardown_group(void **state) {
    (void)state;

    identity_journal_init(NULL);
    unlink(JOURNAL_PATH);
    rmdir("queue/authd");
    rmdir("queue");
    assert_int_equal(chdir(test_cwd), 0);
    rmdir(test_dir);

    return 0;
}

/// Every case starts from an empty journal, in memory and on disk.
static int setup_case(void **state) {
    (void)state;

    unlink(JOURNAL_PATH);
    identity_journal_init(JOURNAL_PATH);

    return 0;
}

/// A keystore holding one agent, built by hand.
///
/// Not OS_AddNewAgent() and not OS_AddKey(): both end up in OS_IsValidIP(), which runs a pcre2
/// match, and pcre2 is a wrapped symbol in this tree -- every case would have to feed mock values
/// for a regex that has nothing to do with the journal. Reconciliation looks at exactly two
/// things, the id in the tree and the raw key on the entry, so those are what the fixture builds.
static void keys_with(const char *id, const char *key) {
    memset(&keys, 0, sizeof(keys));
    keys.keytree_id = rbtree_init();
    assert_non_null(keys.keytree_id);
    os_calloc(2, sizeof(keyentry *), keys.keyentries);
    os_calloc(1, sizeof(keyentry), keys.keyentries[0]);
    keys.keysize = 0;

    if (!id) {
        return;
    }

    keyentry *entry = keys.keyentries[0];
    entry->keyid = 0;
    os_strdup(id, entry->id);
    os_strdup(key, entry->raw_key);
    rbtree_insert(keys.keytree_id, entry->id, entry);
    keys.keysize = 1;
    os_calloc(1, sizeof(keyentry), keys.keyentries[1]);
}

static void keys_clear(void) {
    unsigned int i;

    for (i = 0; i <= keys.keysize; i++) {
        os_free(keys.keyentries[i]->id);
        os_free(keys.keyentries[i]->raw_key);
        os_free(keys.keyentries[i]);
    }

    os_free(keys.keyentries);
    rbtree_destroy(keys.keytree_id);
    memset(&keys, 0, sizeof(keys));
}

static size_t file_lines(void) {
    FILE *fp = fopen(JOURNAL_PATH, "r");
    char line[OS_MAXSTR];
    size_t lines = 0;

    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        lines++;
    }

    fclose(fp);
    return lines;
}

/* --- What is recorded, and how ----------------------------------------------------------------- */

static void test_an_appended_transition_is_readable_after_a_restart(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    long long seq = 0;
    assert_true(identity_journal_append("001", "agent-one", "10.0.0.1", KEY_A, SECRET_A, false, &seq));
    assert_int_equal(seq, 1);
    assert_int_equal(identity_journal_pending(), 1);

    // The restart: nothing in memory, everything from the file.
    identity_journal_init(JOURNAL_PATH);
    assert_int_equal(identity_journal_pending(), 0);
    identity_journal_load();
    assert_int_equal(identity_journal_pending(), 1);

    size_t count = 0;
    identity_journal_entry_t *entries = identity_journal_snapshot(0, &count);
    assert_int_equal(count, 1);
    assert_string_equal(entries[0].id, "001");
    assert_string_equal(entries[0].name, "agent-one");
    assert_string_equal(entries[0].ip, "10.0.0.1");
    assert_string_equal(entries[0].key, KEY_A);
    // The credential itself, not a digest of it: the verifier derives its signing key from the
    // real secret, so a hash would record that a rotation happened and restore nothing.
    assert_string_equal(entries[0].secret, SECRET_A);
    assert_false(entries[0].rotate);
    identity_journal_free(entries, count);
}

static void test_the_file_is_not_world_readable(void **state) {
    (void)state;

    assert_true(identity_journal_append("002", "agent-two", "any", KEY_A, SECRET_A, true, NULL));

    struct stat info;
    assert_int_equal(stat(JOURNAL_PATH, &info), 0);
    // It carries credentials from the first byte: no window with the process umask.
    assert_int_equal(info.st_mode & 07777, 0640);
}

static void test_appending_does_not_rewrite_what_is_already_there(void **state) {
    (void)state;

    assert_true(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, false, NULL));
    assert_true(identity_journal_append("002", "two", "any", KEY_B, SECRET_B, true, NULL));

    // One line per transition, in order, and the second append did not touch the first.
    assert_int_equal(file_lines(), 2);
    assert_int_equal(identity_journal_pending(), 2);
}

static void test_a_torn_last_line_does_not_cost_the_ones_before_it(void **state) {
    (void)state;
    EXPECT_LOG_WARN();
    EXPECT_LOG_INFO();

    assert_true(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, false, NULL));

    // The shape of a crash mid-append: a complete line, then half of one.
    FILE *fp = fopen(JOURNAL_PATH, "a");
    assert_non_null(fp);
    assert_true(fputs("{\"seq\":2,\"id\":\"002\",\"rot", fp) >= 0);
    assert_int_equal(fclose(fp), 0);

    identity_journal_init(JOURNAL_PATH);
    identity_journal_load();

    assert_int_equal(identity_journal_pending(), 1);
}

static void test_a_file_past_the_byte_ceiling_is_not_loaded(void **state) {
    (void)state;
    EXPECT_LOG_ERROR();

    FILE *fp = fopen(JOURNAL_PATH, "w");
    assert_non_null(fp);
    assert_int_equal(ftruncate(fileno(fp), IDENTITY_JOURNAL_MAX_BYTES + 1), 0);
    assert_int_equal(fclose(fp), 0);

    identity_journal_init(JOURNAL_PATH);
    identity_journal_load();

    // Nothing is loaded: a file that size is corruption, not a busy manager -- the admission bound
    // keeps a legitimate one two orders of magnitude below it.
    assert_int_equal(identity_journal_pending(), 0);
}

static void test_an_unwritable_path_refuses_the_transition(void **state) {
    (void)state;
    EXPECT_LOG_ERROR();

    identity_journal_init("queue/no-such-directory/pending-identities");

    // false is the whole point: the caller must NOT hand out a credential it could not record.
    assert_false(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, false, NULL));
    assert_int_equal(identity_journal_pending(), 0);
}

static void test_the_backlog_bound_refuses_new_transitions_and_keeps_the_old(void **state) {
    (void)state;
    EXPECT_LOG_WARN();

    char id[16];
    int i;

    for (i = 0; i < IDENTITY_JOURNAL_MAX_ENTRIES; i++) {
        snprintf(id, sizeof(id), "%d", i + 1);
        assert_true(identity_journal_append(id, "agent", "any", KEY_A, SECRET_A, false, NULL));
    }

    assert_int_equal(identity_journal_pending(), IDENTITY_JOURNAL_MAX_ENTRIES);
    // The one that does not fit is refused; every line already there is a credential some agent
    // holds, so none of them is dropped to make room.
    assert_false(identity_journal_append("99999", "agent", "any", KEY_A, SECRET_A, false, NULL));
    assert_int_equal(identity_journal_pending(), IDENTITY_JOURNAL_MAX_ENTRIES);
}

/* --- Forgetting, once the database has it ------------------------------------------------------ */

static void test_dropping_an_entry_shortens_the_file(void **state) {
    (void)state;

    long long first = 0;
    long long second = 0;
    assert_true(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, false, &first));
    assert_true(identity_journal_append("002", "two", "any", KEY_B, SECRET_B, true, &second));

    assert_int_equal(identity_journal_drop(&first, 1), 1);
    assert_int_equal(identity_journal_pending(), 1);
    assert_int_equal(file_lines(), 1);

    // Idempotent: the writer may commit the same batch twice after a retry.
    assert_int_equal(identity_journal_drop(&first, 1), 0);

    size_t count = 0;
    identity_journal_entry_t *entries = identity_journal_snapshot(0, &count);
    assert_int_equal(count, 1);
    assert_string_equal(entries[0].id, "002");
    identity_journal_free(entries, count);
}

static void test_a_snapshot_is_bounded_by_the_batch(void **state) {
    (void)state;

    assert_true(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, false, NULL));
    assert_true(identity_journal_append("002", "two", "any", KEY_B, SECRET_B, false, NULL));
    assert_true(identity_journal_append("003", "three", "any", KEY_A, SECRET_B, false, NULL));

    size_t count = 0;
    identity_journal_entry_t *entries = identity_journal_snapshot(2, &count);
    assert_int_equal(count, 2);
    // Oldest first: a retry works through the backlog in the order it was created.
    assert_string_equal(entries[0].id, "001");
    identity_journal_free(entries, count);

    // And the journal itself is untouched by looking at it.
    assert_int_equal(identity_journal_pending(), 3);
}

/* --- What a line from a dead process means ----------------------------------------------------- */

static void test_reconciliation_keeps_the_live_generation(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    keys_with("001", KEY_A);
    assert_true(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, true, NULL));

    // Nothing later names this agent, so the database is the one that is behind.
    assert_int_equal(identity_journal_reconcile(), 1);
    assert_int_equal(identity_journal_pending(), 1);

    // And the rotation is reserved again: until the recovery commits, the database still names the
    // previous secret, which is exactly what must not authorise a second rotation.
    assert_false(w_reenroll_reserve("001", NULL));
    w_reenroll_complete("001");

    keys_clear();
}

static void test_reconciliation_keeps_a_rotation_client_keys_never_received(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    // The crash this journal exists for: the answer went out, and authd died before the writer
    // rewrote client.keys. The file still names the OLD key; the entry names what the agent holds.
    keys_with("002", KEY_A);
    assert_true(identity_journal_append("002", "two", "any", KEY_B, SECRET_B, true, NULL));

    // Judging by client.keys would call this "superseded" and delete the only durable copy of the
    // credentials the agent is already using, leaving it unable to connect OR to re-enroll.
    assert_int_equal(identity_journal_reconcile(), 1);
    assert_int_equal(identity_journal_pending(), 1);

    size_t count = 0;
    identity_journal_entry_t *entries = identity_journal_snapshot(0, &count);
    assert_int_equal(count, 1);
    assert_string_equal(entries[0].secret, SECRET_B);
    identity_journal_free(entries, count);

    assert_false(w_reenroll_reserve("002", NULL));
    w_reenroll_complete("002");

    keys_clear();
}

/* Replaces an earlier case that asserted the opposite: that an entry whose key differs from
 * client.keys is superseded. That rule discarded the live credentials of a rotation the writer had
 * not got to yet (issue #39078, review round), so what supersedes an entry is now a LATER entry for
 * the same agent -- which is what this case fixes. */
static void test_reconciliation_keeps_only_the_newest_entry_of_an_agent(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    // Two rotations of one agent survived a restart -- possible only across a crash, since the
    // reservation forbids it while the process lives. The journal's own order says which is live.
    keys_with("003", KEY_B);
    assert_true(identity_journal_append("003", "three", "any", KEY_A, SECRET_A, true, NULL));
    assert_true(identity_journal_append("003", "three", "any", KEY_B, SECRET_B, true, NULL));

    assert_int_equal(identity_journal_reconcile(), 1);

    size_t count = 0;
    identity_journal_entry_t *entries = identity_journal_snapshot(0, &count);
    assert_int_equal(count, 1);
    // The newest one: writing the older secret back would hand the agent's identity to a bearer it
    // has already replaced.
    assert_string_equal(entries[0].secret, SECRET_B);
    identity_journal_free(entries, count);

    assert_false(w_reenroll_reserve("003", NULL));
    w_reenroll_complete("003");

    keys_clear();
}

static void test_reconciliation_discards_a_transition_whose_agent_is_gone(void **state) {
    (void)state;
    EXPECT_LOG_INFO();

    keys_with(NULL, NULL);
    assert_true(identity_journal_append("001", "one", "any", KEY_A, SECRET_A, false, NULL));

    // Deleted while the write was owed, or its client.keys write never landed: either way the
    // database must not be given a row for it.
    assert_int_equal(identity_journal_reconcile(), 0);
    assert_int_equal(identity_journal_pending(), 0);

    keys_clear();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_an_appended_transition_is_readable_after_a_restart, setup_case),
        cmocka_unit_test_setup(test_the_file_is_not_world_readable, setup_case),
        cmocka_unit_test_setup(test_appending_does_not_rewrite_what_is_already_there, setup_case),
        cmocka_unit_test_setup(test_a_torn_last_line_does_not_cost_the_ones_before_it, setup_case),
        cmocka_unit_test_setup(test_a_file_past_the_byte_ceiling_is_not_loaded, setup_case),
        cmocka_unit_test_setup(test_an_unwritable_path_refuses_the_transition, setup_case),
        cmocka_unit_test_setup(test_the_backlog_bound_refuses_new_transitions_and_keeps_the_old, setup_case),
        cmocka_unit_test_setup(test_dropping_an_entry_shortens_the_file, setup_case),
        cmocka_unit_test_setup(test_a_snapshot_is_bounded_by_the_batch, setup_case),
        cmocka_unit_test_setup(test_reconciliation_keeps_the_live_generation, setup_case),
        cmocka_unit_test_setup(test_reconciliation_keeps_a_rotation_client_keys_never_received, setup_case),
        cmocka_unit_test_setup(test_reconciliation_keeps_only_the_newest_entry_of_an_agent, setup_case),
        cmocka_unit_test_setup(test_reconciliation_discards_a_transition_whose_agent_is_gone, setup_case),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}

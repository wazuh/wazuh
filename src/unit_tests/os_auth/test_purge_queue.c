/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The queue of pending indexer purges: what authd still owes the inventory sync server after an
 * agent is deleted. What matters here is everything that survives a restart -- the file, the id
 * high-water mark and the clock rules -- because that is what keeps a delayed purge from either
 * being lost or firing at a NEW agent that inherited the same id.
 *
 * Two things shape how these cases are written. The log functions are wrapped, so every line the
 * code under test emits has to be declared, in order; and an undeclared one aborts cmocka from
 * inside a locked section, which would leave mutex_purge held and hang the run. That is why setup
 * pre-creates the file (TempFile() logs when it writes a path that does not exist yet) and starts
 * the id counter high (so the "raising the id counter" line only fires in the case that wants it).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "auth.h"
#include "sec.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/// Higher than any id these cases store, so loading never has to raise it.
#define SETTLED_ID_COUNTER 9999

/* The pending-removal queue add_remove() appends to. Declared here the way main-server.c does, since
 * that file is deliberately left out of authd_lib and cannot set the tail up for us. */
extern struct keynode *queue_remove;
extern struct keynode * volatile *remove_tail;

/* Real files: these functions exist in order to persist, so stubbing the file away would leave
 * nothing worth testing. */
static int setup_queue(void **state) {
    (void)state;

    mkdir("queue", 0770);
    mkdir(AUTHD_QUEUE_DIR, 0770);

    FILE *fp = fopen(PENDING_PURGES_FILE, "w");
    assert_non_null(fp);
    fclose(fp);

    config.purge_delay = 0; // due immediately, so nothing here has to wait
    keys.id_counter = SETTLED_ID_COUNTER;

    return 0;
}

static int teardown_queue(void **state) {
    (void)state;

    unlink(PENDING_PURGES_FILE);

    return 0;
}

/// Read the file back, so the assertions look at what a restart would actually see.
static char* read_purge_file(void) {
    FILE *fp = fopen(PENDING_PURGES_FILE, "r");
    static char content[4096];
    size_t read_bytes;

    memset(content, 0, sizeof(content));
    if (!fp) {
        return content;
    }

    read_bytes = fread(content, 1, sizeof(content) - 1, fp);
    content[read_bytes] = '\0';
    fclose(fp);

    return content;
}

static void write_purge_file(const char *content) {
    FILE *fp = fopen(PENDING_PURGES_FILE, "w");

    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

/* ---------------------------------------------------------------------------------- the queue */

static void test_push_marks_the_id_as_pending_and_persists_it(void **state) {
    (void)state;

    assert_false(purge_is_pending("004"));

    purge_queue_push("004");

    /* Pending is what keeps the id from being handed out again while the purge is in flight. */
    assert_true(purge_is_pending("004"));
    assert_non_null(strstr(read_purge_file(), "purge 004 "));
    assert_non_null(strstr(read_purge_file(), "last_update "));

    /* And dropping it clears both the queue and the file, which is the relay's confirmation path. */
    purge_queue_drop_head();
    assert_false(purge_is_pending("004"));
    assert_null(strstr(read_purge_file(), "purge 004"));
}

static void test_an_id_is_pending_from_the_moment_the_agent_leaves_the_keystore(void **state) {
    (void)state;

    /* add_remove() is the one point both the local socket and a force-replacement funnel through, and
     * it runs before the deletion is answered -- while the purge is only queued later, by the writer.
     * If the id were only refused from the queue onward, an insertion naming it inside that window
     * would take an id whose purge is already on its way, and that purge would delete the new agent's
     * documents. So the reservation has to start here. */
    struct keynode *node;
    os_ip entry_ip = { .ip = "any" };
    keyentry entry = { .id = "007", .name = "removed-agent", .ip = &entry_ip };

    remove_tail = &queue_remove;
    assert_false(purge_is_pending("007"));

    add_remove(&entry);
    assert_true(purge_is_pending("007"));

    /* The writer takes over: still pending, now durably. */
    purge_queue_push("007");
    assert_true(purge_is_pending("007"));
    assert_non_null(strstr(read_purge_file(), "purge 007 "));

    /* And only the relay's confirmation frees the id. */
    purge_queue_drop_head();
    assert_false(purge_is_pending("007"));

    while ((node = queue_remove) != NULL) {
        queue_remove = node->next;
        os_free(node->id);
        os_free(node->name);
        os_free(node->ip);
        os_free(node);
    }
    remove_tail = &queue_remove;
}

static void test_a_due_entry_is_handed_over_without_being_removed(void **state) {
    (void)state;

    purge_queue_push("006");

    char *agent_id = purge_queue_peek_due();

    assert_non_null(agent_id);
    assert_string_equal("006", agent_id);
    /* Peeked, NOT removed: it stays queued until the relay confirms the server took it, so a crash
     * mid-request replays the purge instead of losing it. */
    assert_true(purge_is_pending("006"));
    os_free(agent_id);

    purge_queue_drop_head();
}

/* ----------------------------------------------------------------- the id high-water mark */

static void test_the_id_counter_only_ever_grows(void **state) {
    (void)state;

    expect_any(__wrap__mdebug2, formatted_msg); // the mark grew
    purge_last_id_update(42);
    assert_non_null(strstr(read_purge_file(), "last_id 42"));

    /* A lower value cannot walk it back -- that is the whole point: deleting the highest agents
     * removes them from client.keys, and this mark must not follow them down. */
    purge_last_id_update(7);
    assert_non_null(strstr(read_purge_file(), "last_id 42"));
}

static void test_loading_raises_the_id_counter_past_every_stored_id(void **state) {
    (void)state;

    write_purge_file("last_update 1000\nlast_id 250\npurge 249 1000\n");

    keys.id_counter = 100; // as OS_ReadKeys leaves it once 249 and 250 are gone from client.keys

    expect_any(__wrap__minfo, formatted_msg); // recovered 1 pending deletion
    expect_any(__wrap__minfo, formatted_msg); // raising the id counter
    purge_file_load();

    /* Without this, the next enrollment would be handed 250 -- while 249's purge is still pending,
     * and that purge deletes by agent id. */
    assert_int_equal(250, keys.id_counter);
    assert_true(purge_is_pending("249"));

    purge_queue_drop_head();
}

/* --------------------------------------------------------------------------------- loading rules */

static void test_loading_ignores_unknown_labels_and_malformed_entries(void **state) {
    (void)state;

    write_purge_file("last_update 1000\n"
                     "something_new 1\n" // a newer format's line: ignored, not fatal
                     "purge notanid 1000\n"
                     "purge 007 1000\n");

    expect_any(__wrap__mdebug2, formatted_msg); // ignoring the unknown label
    expect_any(__wrap__mwarn, formatted_msg);   // the malformed entry
    expect_any(__wrap__minfo, formatted_msg);   // recovered 1 pending deletion
    purge_file_load();

    assert_true(purge_is_pending("007"));
    assert_false(purge_is_pending("notanid"));

    purge_queue_drop_head();
}

static void test_a_clock_that_went_backwards_restamps_every_entry(void **state) {
    (void)state;

    /* last_update in the year 2100: whatever the stored timestamps say, they cannot be trusted. */
    write_purge_file("last_update 4102444800\nlast_id 3\npurge 003 4102444800\n");

    expect_any(__wrap__mwarn, formatted_msg); // the clock moved backwards
    expect_any(__wrap__minfo, formatted_msg); // recovered 1 pending deletion
    purge_file_load();

    assert_true(purge_is_pending("003"));

    /* Re-stamped to now, so the entry waits its full delay again instead of firing on a timestamp
     * whose delay never actually elapsed. Pushing a second id rewrites the file, which is how the
     * new stamp becomes observable. */
    purge_queue_push("008");
    assert_null(strstr(read_purge_file(), "purge 003 4102444800"));
    assert_non_null(strstr(read_purge_file(), "purge 003 "));

    purge_queue_drop_head();
    purge_queue_drop_head();
}

static void test_a_missing_file_is_not_an_error(void **state) {
    (void)state;

    unlink(PENDING_PURGES_FILE);

    /* First start ever, or a manager that never deleted an agent: nothing to say about it. */
    purge_file_load();

    assert_false(purge_is_pending("001"));
}

static void test_stopping_releases_the_relay(void **state) {
    (void)state;

    purge_queue_stop();

    /* NULL rather than a blocked thread: this is what lets a shutdown finish instead of waiting out
     * the retry budget of every queued deletion. */
    assert_null(purge_queue_peek_due());
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_push_marks_the_id_as_pending_and_persists_it, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_an_id_is_pending_from_the_moment_the_agent_leaves_the_keystore,
                                        setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_a_due_entry_is_handed_over_without_being_removed, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_the_id_counter_only_ever_grows, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_loading_raises_the_id_counter_past_every_stored_id, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_loading_ignores_unknown_labels_and_malformed_entries, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_a_clock_that_went_backwards_restamps_every_entry, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_a_missing_file_is_not_an_error, setup_queue, teardown_queue),
        /* Last on purpose: stopping the queue is a one-way door for the whole process. */
        cmocka_unit_test_setup_teardown(test_stopping_releases_the_relay, setup_queue, teardown_queue),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The agent-deletion handoff journal: what authd records between removing an agent from
 * client.keys and having a durable manager-task row for its indexer purge.
 *
 * What matters here is everything that survives a restart -- the file, the sequences, the id
 * high-water mark and the clock rules -- because that is what keeps a deletion from either being
 * lost or firing at a NEW agent that inherited the same id. The phase ORDER itself lives in the
 * writer thread (main-server.c, outside authd_lib) and is covered by the integration suite; what is
 * testable here is every decision the phases delegate to this file.
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
#include "manager_task_op.h"
#include "sec.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/// Higher than any id these cases store, so loading never has to raise it.
#define SETTLED_ID_COUNTER 9999

/* The pending-removal queue add_remove() appends to. Declared here the way main-server.c does, since
 * that file is deliberately left out of authd_lib and cannot set the tail up for us. */
extern struct keynode *queue_remove;
extern struct keynode * volatile *remove_tail;

/* auth.c's file-scope state, reachable because it #defines static away under WAZUH_UNIT_TESTING.
 * These three deliberately live for the whole process -- a sequence and an id mark must never
 * rewind -- so the fixtures below reset them, or one case's marks would silently decide what the
 * next case sees. */
extern unsigned int purge_journal_size;
extern int purge_last_id;
extern long long purge_last_seq;

/* --- The wazuh-db seam ---------------------------------------------------------------------------
 *
 * Wrapped rather than reached: this is the only call this file makes outside the process, and what
 * the tests are about is how its ANSWERS are interpreted -- an outstanding row, a terminal one, an
 * absent one, and a query that failed.
 *
 * Every expectation declared here must be consumed, which is what lets a case prove the OPPOSITE
 * too: a case that queues no answer and still passes has shown that the question was settled from
 * memory, without a round trip. */

int __wrap_manager_task_agent_status(const char *agent_id, const char *task_type, int timeout) {
    check_expected(agent_id);
    (void)task_type;
    (void)timeout;
    return mock_type(int);
}

/// Queue one answer from the row for @p agent_id.
static void expect_row_status(const char *agent_id, int status) {
    expect_string(__wrap_manager_task_agent_status, agent_id, agent_id);
    will_return(__wrap_manager_task_agent_status, status);
}

/* Real files: these functions exist in order to persist, so stubbing the file away would leave
 * nothing worth testing. */
static int setup_journal(void **state) {
    (void)state;

    mkdir("queue", 0770);
    mkdir(AUTHD_QUEUE_DIR, 0770);

    FILE *fp = fopen(PENDING_PURGES_FILE, "w");
    assert_non_null(fp);
    fclose(fp);

    config.purge_delay = 0;
    config.wdb_timeout = 10;
    config.max_pending_deletes = 0; // the backlog term is off unless a case turns it on
    purge_last_id = 0;
    purge_last_seq = 0;

    /* The keystore reconciliation is judged against. Built by hand rather than through
     * OS_ReadKeys(), which would need a client.keys on disk: the only thing these cases ask of it
     * is OS_IsAllowedID(), and rbtree_get() asserts on a NULL tree. */
    keys.keytree_id = rbtree_init();
    keys.keytree_ip = rbtree_init();
    keys.keytree_sock = rbtree_init();
    w_mutex_init(&keys.keytree_sock_mutex, NULL);
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    keys.keysize = 0;
    os_calloc(1, sizeof(keyentry), keys.keyentries[0]);
    w_mutex_init(&keys.keyentries[0]->mutex, NULL);
    keys.id_counter = SETTLED_ID_COUNTER;

    return 0;
}

static int teardown_journal(void **state) {
    (void)state;

    unlink(PENDING_PURGES_FILE);

    /* Several cases end with deletions still journaled, which discard() reports -- and an
     * undeclared log line aborts cmocka from inside the locked section, leaving mutex_purge held
     * and hanging the rest of the run. Read from the journal itself rather than tracked per case,
     * so a case that starts or stops leaving work owed needs no change here. */
    if (purge_journal_size > 0) {
        expect_any(__wrap__minfo, formatted_msg);
    }

    purge_journal_discard();

    OS_FreeKeys(&keys);
    memset(&keys, 0, sizeof(keys));

    return 0;
}

/// Read the file back, so the assertions look at what a restart would actually see.
static char* read_journal_file(void) {
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

static void write_journal_file(const char *content) {
    FILE *fp = fopen(PENDING_PURGES_FILE, "w");

    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

/// Journal one id and hand back its entry, the way the writer's phase 1 does.
static purge_journal_entry_t* journal_one(const char *agent_id) {
    char *ids[1] = {(char *)agent_id};

    return purge_journal_append(ids, 1);
}

/* Make one id look enrolled, the way OS_ReadKeys() would have left it.
 *
 * Not OS_AddKey(): that validates the IP through OS_IsValidIP(), which compiles a regex, and pcre2
 * is wrapped in this binary -- so the call would demand mocks for machinery no case here is about.
 * Reconciliation asks exactly one thing of the keystore, OS_IsAllowedID(), which is a lookup on the
 * id tree. The entry is registered in keyentries[] as well so OS_FreeKeys() owns it; rbtree_init()
 * sets no dispose function, so the tree does not free it a second time. */
static void enroll_id(const char *agent_id) {
    keyentry **grown = (keyentry **)realloc(keys.keyentries, (keys.keysize + 2) * sizeof(keyentry *));

    assert_non_null(grown);
    keys.keyentries = grown;

    // Keep the sentinel entry OS_ReadKeys() leaves at keysize.
    keys.keyentries[keys.keysize + 1] = keys.keyentries[keys.keysize];

    os_calloc(1, sizeof(keyentry), keys.keyentries[keys.keysize]);
    os_strdup(agent_id, keys.keyentries[keys.keysize]->id);
    keys.keyentries[keys.keysize]->keyid = keys.keysize;
    keys.keyentries[keys.keysize]->sock = -1;
    w_mutex_init(&keys.keyentries[keys.keysize]->mutex, NULL);

    rbtree_insert(keys.keytree_id, keys.keyentries[keys.keysize]->id, keys.keyentries[keys.keysize]);
    keys.keysize++;
}

/* ------------------------------------------------------------------------------- phase 1 and 4 */

static void test_journaling_records_the_id_and_persists_it(void **state) {
    (void)state;

    /* Nothing journaled yet, so the only authority is the row, and there is none. */
    expect_row_status("004", MANAGER_TASK_STATUS_NONE);
    assert_false(purge_is_pending("004"));

    purge_journal_entry_t *entry = journal_one("004");

    assert_non_null(entry);
    assert_string_equal("004", entry->id);
    assert_int_equal(1, entry->journal_seq);

    /* Pending straight from memory: the journal is authd's own record, so no query is needed to
     * trust it -- and this case queues no wazuh-db answer, which is what proves that. */
    assert_true(purge_is_pending("004"));
    assert_non_null(strstr(read_journal_file(), "purge 004 "));
    assert_non_null(strstr(read_journal_file(), "last_seq 1"));

    /* Phase 4 clears the line, and with it authd's own record of the deletion. The id is not free,
     * though: the row exists now, and from here only its status can say so. */
    purge_journal_drop(entry, 1);
    assert_null(strstr(read_journal_file(), "purge 004"));

    expect_row_status("004", MANAGER_TASK_STATUS_OUTSTANDING);
    assert_true(purge_is_pending("004"));

    os_free(entry);
}

static void test_an_id_is_covered_from_the_moment_the_agent_leaves_the_keystore(void **state) {
    (void)state;

    /* add_remove() is the one point both the local socket and a force-replacement funnel through,
     * and it runs before the deletion is answered -- while the journal line is only written later,
     * by the writer. If the id were only refused from the journal onward, an insertion naming it
     * inside that window would take an id whose purge is already on its way, and that purge would
     * delete the new agent's documents. So the reservation has to start here, and the handoff to the
     * journal has to be atomic. */
    struct keynode *node;
    os_ip entry_ip = { .ip = "any" };
    keyentry entry = { .id = "007", .name = "removed-agent", .ip = &entry_ip };

    remove_tail = &queue_remove;
    expect_row_status("007", MANAGER_TASK_STATUS_NONE);
    assert_false(purge_is_pending("007"));

    /* From here on the answer comes from memory: no case below queues a wazuh-db answer, and an
     * unexpected call would fail. */
    add_remove(&entry);
    assert_true(purge_is_pending("007"));

    /* The writer takes over: still pending, now durably, and still without a query. The handoff
     * from the reservation to the journal happens under one lock, so no instant is uncovered. */
    purge_journal_entry_t *journaled = journal_one("007");
    assert_true(purge_is_pending("007"));
    assert_non_null(strstr(read_journal_file(), "purge 007 "));

    os_free(journaled);

    while ((node = queue_remove) != NULL) {
        queue_remove = node->next;
        os_free(node->id);
        os_free(node->name);
        os_free(node->ip);
        os_free(node);
    }
    remove_tail = &queue_remove;
}

static void test_dropping_matches_on_the_sequence_not_the_id(void **state) {
    (void)state;

    /* One agent can hold two journal lines at once: deleted, re-enrolled and deleted again inside a
     * single writer cycle. Dropping by id would forget the wrong one and leave the other owed
     * forever, with no line and no row behind it. */
    purge_journal_entry_t *first = journal_one("011");
    purge_journal_entry_t *second = journal_one("011");

    assert_int_equal(1, first->journal_seq);
    assert_int_equal(2, second->journal_seq);

    purge_journal_drop(first, 1);

    assert_null(strstr(read_journal_file(), "purge 011 0 1\n"));
    assert_non_null(strstr(read_journal_file(), " 2\n"));

    os_free(first);
    os_free(second);
}

static void test_sequences_never_repeat_across_a_restart(void **state) {
    (void)state;

    /* Two deletions of one agent must derive two DIFFERENT task ids, or the second one collides
     * with the first and is silently swallowed as "already recorded" -- including against a
     * completed row still inside the retention window. A restart must not reset the counter. */
    purge_journal_entry_t *first = journal_one("012");
    assert_int_equal(1, first->journal_seq);
    purge_journal_drop(first, 1);
    os_free(first);

    /* The line is gone, but the high-water mark is not. */
    assert_non_null(strstr(read_journal_file(), "last_seq 1"));

    purge_journal_discard();
    purge_file_load();

    purge_journal_entry_t *second = journal_one("012");
    assert_int_equal(2, second->journal_seq);
    os_free(second);
}

/* --------------------------------------------------------------------------- phase 0: admission */

static void test_the_backlog_bound_counts_reservations_too(void **state) {
    (void)state;

    /* Not the journal alone. Phase 0 runs on request threads while phase 1 appends at writer time,
     * so a burst would each see "not full", all pass, and phase 1 would overflow where refusal is no
     * longer possible. This case only pins that a reservation is visible to the check at all -- the
     * limit itself is 65536, which no unit test is going to fill. */
    os_ip entry_ip = { .ip = "any" };
    keyentry entry = { .id = "021", .name = "removed-agent", .ip = &entry_ip };
    struct keynode *node;

    remove_tail = &queue_remove;
    assert_false(purge_backlog_full());

    add_remove(&entry);

    /* Reserved but not journaled: the id is in flight, and it counts -- from memory, which is what
     * queuing no wazuh-db answer here proves. */
    assert_true(purge_is_pending("021"));

    while ((node = queue_remove) != NULL) {
        queue_remove = node->next;
        os_free(node->id);
        os_free(node->name);
        os_free(node->ip);
        os_free(node);
    }
    remove_tail = &queue_remove;
}

static void test_a_full_row_backlog_refuses_the_deletion(void **state) {
    (void)state;

    config.max_pending_deletes = 2;

    purge_pending_rows_update(1);
    assert_false(purge_backlog_full());

    expect_any(__wrap__mwarn, formatted_msg); // refusing: the backlog is full
    purge_pending_rows_update(2);
    assert_true(purge_backlog_full());
}

static void test_a_failed_measurement_keeps_the_previous_backlog_depth(void **state) {
    (void)state;

    /* Fails OPEN, and this is the direction that matters: reporting a failed count as zero would
     * lift the bound for exactly as long as wazuh-db is unreachable, which is when the backlog is
     * least likely to be draining. Reporting it as full would block deletion during an outage. */
    config.max_pending_deletes = 2;

    expect_any(__wrap__mwarn, formatted_msg);
    purge_pending_rows_update(5);
    assert_true(purge_backlog_full());

    purge_pending_rows_update(-1); // the count query failed

    expect_any(__wrap__mwarn, formatted_msg);
    assert_true(purge_backlog_full());
}

/* ------------------------------------------------------------------ the reusable-id guard */

static void test_a_terminal_row_frees_the_id(void **state) {
    (void)state;

    /* Once phase 4 has dropped the line, authd holds no record of the deletion at all, and the row
     * is the only thing that can say whether the id is free. */
    purge_journal_entry_t *entry = journal_one("031");
    purge_journal_drop(entry, 1);
    os_free(entry);

    expect_row_status("031", MANAGER_TASK_STATUS_TERMINAL);
    assert_false(purge_is_pending("031"));
}

static void test_the_row_is_asked_again_every_time(void **state) {
    (void)state;

    /* No local mirror of the outstanding rows sits in front of this query, and that is a decision
     * rather than an omission. A set authd adds to at phase 1 can only shrink when someone happens
     * to look up that exact id, so it grows without bound on a manager that churns agents -- and
     * every phase 1 would then scan it under mutex_purge. One round trip on the explicit-id
     * insertion path is the cheaper side of that trade.
     *
     * Both answers below have to be consumed, which is what pins "asked again": with a cache the
     * second call would answer from memory and leave the second expectation unconsumed. */
    expect_row_status("034", MANAGER_TASK_STATUS_OUTSTANDING);
    assert_true(purge_is_pending("034"));

    expect_row_status("034", MANAGER_TASK_STATUS_TERMINAL);
    assert_false(purge_is_pending("034"));
}

static void test_an_absent_row_also_frees_the_id(void **state) {
    (void)state;

    /* Reachable rather than hypothetical: a line is journaled at phase 1, OS_WriteKeys then fails,
     * phase 3 is correctly skipped, and reconciliation drops the line without creating a row. The
     * id is then owed nothing by anyone, and NONE has to be read as free rather than as a failure. */
    purge_journal_entry_t *entry = journal_one("032");
    purge_journal_drop(entry, 1);
    os_free(entry);

    expect_row_status("032", MANAGER_TASK_STATUS_NONE);
    assert_false(purge_is_pending("032"));
}

static void test_a_failed_status_query_refuses_the_id(void **state) {
    (void)state;

    /* Refusing reuse is an error an operator can work around; allowing it risks an outstanding
     * purge deleting a NEW agent's documents, which nothing ever repairs. */
    purge_journal_entry_t *entry = journal_one("033");
    purge_journal_drop(entry, 1);
    os_free(entry);

    expect_row_status("033", MANAGER_TASK_STATUS_FAILED);
    expect_any(__wrap__mwarn, formatted_msg);
    assert_true(purge_is_pending("033"));

    /* And a failure is never cached as an answer either: the next attempt asks again. */
    expect_row_status("033", MANAGER_TASK_STATUS_FAILED);
    expect_any(__wrap__mwarn, formatted_msg);
    assert_true(purge_is_pending("033"));
}

static void test_the_memory_only_answer_never_queries(void **state) {
    (void)state;

    /* The variant local_add() calls under mutex_keys, where a wazuh-db round trip would stall the
     * writer thread and every enrollment behind it. It answers from authd's own records only, so it
     * can say "in flight here" but never "the row says it is free" -- and this case queues no
     * wazuh-db answer at all, which is the property that matters. */
    purge_journal_entry_t *entry = journal_one("035");

    assert_true(purge_is_pending_locally("035"));
    assert_false(purge_is_pending_locally("036"));

    purge_journal_drop(entry, 1);

    /* Dropped: authd no longer holds it, so the memory-only answer is "not mine" whatever the row
     * may still say. That is exactly why it is only ever a RE-CHECK, never the whole guard. */
    assert_false(purge_is_pending_locally("035"));

    os_free(entry);
}

/* ---------------------------------------------------------------------- startup reconciliation */

static void test_reconciliation_drops_lines_whose_agent_is_still_enrolled(void **state) {
    (void)state;

    /* The crash between phase 1 and phase 2, and the failed-OS_WriteKeys case, which are
     * indistinguishable from here and resolve identically: the agent is on disk, so it was never
     * deleted and nothing is owed for it. */
    size_t owed_count = 12345;
    purge_journal_entry_t *owed;

    write_journal_file("last_update 1000\nlast_id 9999\nlast_seq 4\npurge 051 1000 4\n");
    purge_file_load();

    enroll_id("051");

    expect_any(__wrap__minfo, formatted_msg); // dropped 1 journaled deletion
    owed = purge_journal_reconcile(&owed_count);

    assert_null(owed);
    assert_int_equal(0, owed_count);
    assert_null(strstr(read_journal_file(), "purge 051"));
}

static void test_reconciliation_keeps_lines_whose_agent_is_gone(void **state) {
    (void)state;

    /* The window this whole design exists to close: the crash between OS_WriteKeys and the row
     * being created. The agent is gone, nobody will ask again, and only the journal knows. */
    size_t owed_count = 0;
    purge_journal_entry_t *owed;

    write_journal_file("last_update 1000\nlast_id 9999\nlast_seq 7\npurge 052 1000 7\n");
    purge_file_load();

    expect_any(__wrap__minfo, formatted_msg); // recovered 1 deletion
    owed = purge_journal_reconcile(&owed_count);

    assert_non_null(owed);
    assert_int_equal(1, owed_count);
    assert_string_equal("052", owed[0].id);
    /* The SAME sequence, so the task id phase 3 would have derived is derived again and the create
     * collides instead of duplicating. */
    assert_int_equal(7, owed[0].journal_seq);
    assert_non_null(strstr(read_journal_file(), "purge 052 "));

    /* And it is pending without a query: the line is still journaled, which is authd's own record
     * and needs no confirmation. This case queues no wazuh-db answer. */
    assert_true(purge_is_pending("052"));

    os_free(owed);
}

/* ------------------------------------------------- what the writer retries after a failed phase 3 */

static void test_a_failed_record_is_still_owed_on_the_next_cycle(void **state) {
    (void)state;

    /* The failure this whole sequence exists to survive: wazuh-db was unreachable when phase 3 ran.
     * The agent is already gone from client.keys, so nothing will ask again -- the journal line is
     * the only record, and the next writer cycle has to find it. It does, because phase 3 works
     * from purge_journal_snapshot() rather than from the ids the failing cycle happened to journal.
     *
     * Read directly rather than through the writer: run_writer() lives in main-server.c, outside
     * authd_lib, and the phase ORDER is the integration suite's. What is testable here is that the
     * line an unrecorded deletion left behind is still on offer afterwards. */
    size_t first_count = 0;
    size_t second_count = 0;
    purge_journal_entry_t *first = NULL;
    purge_journal_entry_t *second = NULL;
    purge_journal_entry_t *journaled = journal_one("061");

    assert_non_null(journaled);

    first = purge_journal_snapshot(&first_count);
    assert_int_equal(1, first_count);
    assert_string_equal("061", first[0].id);

    /* Phase 3 failed, so phase 4 never ran and nothing was dropped. The snapshot still offers it,
     * with the SAME sequence -- so the retry derives the same task id and a create that did land
     * before the failure was reported collides instead of duplicating. */
    second = purge_journal_snapshot(&second_count);
    assert_int_equal(1, second_count);
    assert_string_equal("061", second[0].id);
    assert_int_equal(first[0].journal_seq, second[0].journal_seq);

    // And once it is recorded, the line goes and the next cycle is offered nothing.
    purge_journal_drop(second, 1);
    os_free(second);

    second = purge_journal_snapshot(&second_count);
    assert_int_equal(0, second_count);
    assert_null(second);

    os_free(first);
    os_free(journaled);
}

static void test_the_snapshot_decides_nothing(void **state) {
    (void)state;

    /* Unlike reconcile, it must not drop a line whose agent is back in client.keys, or write the
     * file: it runs on every writer cycle, and a cycle is not the place to re-decide what is owed.
     * Reconciliation owns that, once, at startup. */
    size_t count = 0;
    purge_journal_entry_t *owed = NULL;

    write_journal_file("last_update 1000\nlast_id 9999\nlast_seq 4\npurge 062 1000 4\n");
    purge_file_load();

    enroll_id("062");

    // No expect_any for __wrap__minfo: reconcile logs what it drops, and this must log nothing.
    owed = purge_journal_snapshot(&count);

    assert_int_equal(1, count);
    assert_string_equal("062", owed[0].id);
    assert_non_null(strstr(read_journal_file(), "purge 062 "));

    os_free(owed);
}

/* ----------------------------------------------------------------- the id high-water mark */

static void test_the_id_counter_only_ever_grows(void **state) {
    (void)state;

    expect_any(__wrap__mdebug2, formatted_msg); // the mark grew
    purge_last_id_update(42);
    assert_non_null(strstr(read_journal_file(), "last_id 42"));

    /* A lower value cannot walk it back -- that is the whole point: deleting the highest agents
     * removes them from client.keys, and this mark must not follow them down. */
    purge_last_id_update(7);
    assert_non_null(strstr(read_journal_file(), "last_id 42"));
}

static void test_loading_raises_the_id_counter_past_every_stored_id(void **state) {
    (void)state;

    write_journal_file("last_update 1000\nlast_id 250\nlast_seq 3\npurge 249 1000 3\n");

    keys.id_counter = 100; // as OS_ReadKeys leaves it once 249 and 250 are gone from client.keys

    expect_any(__wrap__minfo, formatted_msg); // raising the id counter
    purge_file_load();

    /* Without this, the next enrollment would be handed 250 -- while 249's purge is still pending,
     * and that purge deletes by agent id. */
    assert_int_equal(250, keys.id_counter);

    assert_true(purge_is_pending("249"));
}

/* --------------------------------------------------------------------------------- loading rules */

static void test_old_format_entries_are_numbered_by_position(void **state) {
    (void)state;

    /* By POSITION, not by handing each the next value from last_seq. Position is deterministic
     * across a crash during the conversion; a running counter is not, and re-assigning different
     * sequences would derive different task ids and produce DUPLICATE rows for one deletion --
     * breaking "a collision means already recorded" on precisely the path that story exists for. */
    size_t owed_count = 0;
    purge_journal_entry_t *owed;

    write_journal_file("last_update 1000\nlast_id 9999\npurge 061 1000\npurge 062 1000\n");

    expect_any(__wrap__minfo, formatted_msg); // converted 2 entries
    purge_file_load();

    expect_any(__wrap__minfo, formatted_msg); // recovered 2 deletions
    owed = purge_journal_reconcile(&owed_count);

    assert_int_equal(2, owed_count);
    assert_int_equal(1, owed[0].journal_seq);
    assert_int_equal(2, owed[1].journal_seq);

    os_free(owed);
}

static void test_loading_ignores_unknown_labels_and_malformed_entries(void **state) {
    (void)state;

    write_journal_file("last_update 1000\n"
                       "something_new 1\n" // a newer format's line: ignored, not fatal
                       "purge notanid 1000 1\n"
                       "purge 007 1000 2\n");

    expect_any(__wrap__mdebug2, formatted_msg); // ignoring the unknown label
    expect_any(__wrap__mwarn, formatted_msg);   // the malformed entry
    purge_file_load();

    assert_true(purge_is_pending("007"));

    /* And the malformed line left nothing behind. Asked of authd's own records rather than through
     * the full guard, because that is the question this case has: whether the id was dropped at
     * load or carried as an unresolved one. */
    assert_false(purge_is_pending_locally("notanid"));
}

static void test_a_clock_that_went_backwards_restamps_every_entry(void **state) {
    (void)state;

    /* last_update in the year 2100: whatever the stored timestamps say, they cannot be trusted. */
    write_journal_file("last_update 4102444800\nlast_id 9999\nlast_seq 3\npurge 003 4102444800 3\n");

    expect_any(__wrap__mwarn, formatted_msg); // the clock moved backwards
    purge_file_load();

    /* Re-stamped to now, so the deletion waits its full delay again instead of running on a
     * timestamp whose delay never actually elapsed. Journaling a second id rewrites the file, which
     * is how the new stamp becomes observable. */
    purge_journal_entry_t *entry = journal_one("008");
    assert_null(strstr(read_journal_file(), "purge 003 4102444800"));
    assert_non_null(strstr(read_journal_file(), "purge 003 "));

    os_free(entry);
}

static void test_a_missing_file_is_not_an_error(void **state) {
    (void)state;

    unlink(PENDING_PURGES_FILE);

    /* First start ever, or a manager that never deleted an agent: nothing to say about it. */
    purge_file_load();

    assert_false(purge_is_pending_locally("001"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Phases 1 and 4
        cmocka_unit_test_setup_teardown(test_journaling_records_the_id_and_persists_it,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_an_id_is_covered_from_the_moment_the_agent_leaves_the_keystore,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_dropping_matches_on_the_sequence_not_the_id,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_sequences_never_repeat_across_a_restart,
                                        setup_journal, teardown_journal),
        // Phase 0
        cmocka_unit_test_setup_teardown(test_the_backlog_bound_counts_reservations_too,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_a_full_row_backlog_refuses_the_deletion,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_a_failed_measurement_keeps_the_previous_backlog_depth,
                                        setup_journal, teardown_journal),
        // The reusable-id guard
        cmocka_unit_test_setup_teardown(test_a_terminal_row_frees_the_id, setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_the_row_is_asked_again_every_time, setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_an_absent_row_also_frees_the_id, setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_a_failed_status_query_refuses_the_id, setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_the_memory_only_answer_never_queries,
                                        setup_journal, teardown_journal),
        // Startup reconciliation
        cmocka_unit_test_setup_teardown(test_reconciliation_drops_lines_whose_agent_is_still_enrolled,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_reconciliation_keeps_lines_whose_agent_is_gone,
                                        setup_journal, teardown_journal),
        // What the writer retries after a failed phase 3
        cmocka_unit_test_setup_teardown(test_a_failed_record_is_still_owed_on_the_next_cycle,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_the_snapshot_decides_nothing, setup_journal, teardown_journal),
        // The id high-water mark
        cmocka_unit_test_setup_teardown(test_the_id_counter_only_ever_grows, setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_loading_raises_the_id_counter_past_every_stored_id,
                                        setup_journal, teardown_journal),
        // Loading rules
        cmocka_unit_test_setup_teardown(test_old_format_entries_are_numbered_by_position,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_loading_ignores_unknown_labels_and_malformed_entries,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_a_clock_that_went_backwards_restamps_every_entry,
                                        setup_journal, teardown_journal),
        cmocka_unit_test_setup_teardown(test_a_missing_file_is_not_an_error, setup_journal, teardown_journal),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

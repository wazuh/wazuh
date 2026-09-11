/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The one promise of the enrollment token store that no sequential case can pin: a token with
 * `max_uses` N admits exactly N enrollments, however many of them arrive at the same instant.
 *
 * etoken_store_consume() is that promise in full -- the lookup, the three refusals, the `uses++` and
 * the persist are one critical section under etoken_mutex -- and a reader can see as much by looking
 * at it. What a reader cannot see is whether it STAYS that way, and that is what these cases are
 * for. They are the only place in the suite where authd's enrollment threads are reproduced as
 * threads: everywhere else the store is driven one call at a time, which is the shape a lost update
 * hides in.
 *
 * This is a binary of its own, and not for tidiness. Every other os_auth suite links the -Wl,--wrap
 * logging wrappers, and cmocka keeps their expectations in THREAD-LOCAL storage: a log line emitted
 * from a spawned thread looks into an uninitialised map and takes the process down with it, whatever
 * the code under test was doing at the time. So this binary links the real logger instead -- the
 * threads log exactly as authd's own do -- and cmocka is only ever touched from the main thread,
 * after every thread has been joined.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "enrollment_token_store.h"

/// Where the fixture puts the store, relative to the temporary directory it chdir()s into.
#define STORE_PATH "etc/enrollment_tokens.json"

/// Enrollments issued at once. Well above any limit under test, so the losers are the point.
#define CONSUMERS 16

static char test_cwd[PATH_MAX];
static char test_dir[PATH_MAX];

/* --- Fixtures ---------------------------------------------------------------------------------- */

static int setup_group(void **state) {
    (void)state;

    assert_non_null(getcwd(test_cwd, sizeof(test_cwd)));

    snprintf(test_dir, sizeof(test_dir), "/tmp/wazuh_etoken_conc_XXXXXX");
    assert_non_null(mkdtemp(test_dir));
    assert_int_equal(chdir(test_dir), 0);
    assert_int_equal(mkdir("etc", 0770), 0);

    return 0;
}

static int teardown_group(void **state) {
    (void)state;

    unlink(STORE_PATH);
    rmdir("etc");
    assert_int_equal(chdir(test_cwd), 0);
    rmdir(test_dir);

    return 0;
}

static int setup_store(void **state) {
    (void)state;

    etoken_store_free();
    unlink(STORE_PATH);
    etoken_store_init(STORE_PATH);

    return 0;
}

static int teardown_store(void **state) {
    (void)state;

    etoken_store_free();
    unlink(STORE_PATH);

    return 0;
}

/* --- Helpers ----------------------------------------------------------------------------------- */

/// Mint one token and copy out its identifier.
static void mint_token(char *id, size_t size, unsigned int max_uses) {
    etoken_mint_t mint;
    cJSON *data = NULL;
    const cJSON *item = NULL;

    memset(&mint, 0, sizeof(mint));
    os_strdup("wazuh-1", mint.adr);
    mint.has_pin = 1;
    memset(mint.pin, 0xAB, sizeof(mint.pin));
    mint.ttl = 3600;
    mint.max_uses = max_uses;

    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), 0);
    etoken_mint_free(&mint);

    assert_non_null(data);
    item = cJSON_GetObjectItem(data, "id");
    assert_true(cJSON_IsString((cJSON *)item));
    snprintf(id, size, "%s", item->valuestring);
    cJSON_Delete(data);
}

/// The `uses` counter the FILE records for @p id, or -1 when the id is not in it.
static int file_uses_of(const char *id) {
    cJSON *root = json_fread(STORE_PATH, 0);
    cJSON *item = NULL;
    int uses = -1;

    assert_non_null(root);

    cJSON_ArrayForEach(item, cJSON_GetObjectItem(root, "tokens")) {
        const cJSON *token_id = cJSON_GetObjectItem(item, "id");

        if (cJSON_IsString((cJSON *)token_id) && strcmp(token_id->valuestring, id) == 0) {
            uses = cJSON_GetObjectItem(item, "uses")->valueint;
        }
    }

    cJSON_Delete(root);

    return uses;
}

/* Every consumer waits here, so the calls are issued together rather than one after another: a
 * critical section that is only ever entered sequentially is not one a case can prove anything about */
static pthread_barrier_t start_line;

typedef struct {
    const char *id;
    time_t now;
    etoken_use_t result;
} consumer_t;

static void *consume_one(void *arg) {
    consumer_t *consumer = (consumer_t *)arg;

    pthread_barrier_wait(&start_line);
    consumer->result = etoken_store_consume(consumer->id, consumer->now);

    return NULL;
}

/**
 * @brief Run CONSUMERS enrollments against one token at once and count how many were admitted.
 *
 * @param refusal Optional; receives the verdict the refused enrollments were given.
 */
static int admitted_at_once(const char *id, etoken_use_t *refusal) {
    pthread_t threads[CONSUMERS];
    consumer_t consumers[CONSUMERS];
    time_t now = time(NULL);
    int admitted = 0;
    int i;

    assert_int_equal(pthread_barrier_init(&start_line, NULL, CONSUMERS), 0);

    for (i = 0; i < CONSUMERS; i++) {
        consumers[i].id = id;
        consumers[i].now = now;
        consumers[i].result = ETOKEN_USE_OK;
        assert_int_equal(pthread_create(&threads[i], NULL, consume_one, &consumers[i]), 0);
    }

    for (i = 0; i < CONSUMERS; i++) {
        assert_int_equal(pthread_join(threads[i], NULL), 0);
    }

    assert_int_equal(pthread_barrier_destroy(&start_line), 0);

    for (i = 0; i < CONSUMERS; i++) {
        if (consumers[i].result == ETOKEN_USE_OK) {
            admitted++;
        } else if (refusal != NULL) {
            *refusal = consumers[i].result;
        }
    }

    return admitted;
}

/* --- Cases ------------------------------------------------------------------------------------- */

static void test_a_single_use_token_admits_exactly_one_concurrent_enrollment(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    etoken_use_t refusal = ETOKEN_USE_OK;

    mint_token(id, sizeof(id), 1);

    /* `--max-uses 1` is the token an operator hands to ONE machine. Sixteen agents presenting it at
     * the same moment is what a token that got copied looks like in the field, and the answer has to
     * be one enrollment and fifteen refusals -- not "however many got in before the counter caught
     * up with them" */
    assert_int_equal(admitted_at_once(id, &refusal), 1);
    assert_int_equal(refusal, ETOKEN_USE_EXHAUSTED);

    /* And the file says what memory says */
    assert_int_equal(etoken_store_count(), 1);
    assert_int_equal(file_uses_of(id), 1);

    /* The token is spent for good: an enrollment that arrives later is refused too */
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_EXHAUSTED);
}

static void test_a_limited_token_admits_exactly_its_max_uses(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    etoken_use_t refusal = ETOKEN_USE_OK;

    mint_token(id, sizeof(id), 4);

    /* The same rule with room for four: a limit is a count, not a rate */
    assert_int_equal(admitted_at_once(id, &refusal), 4);
    assert_int_equal(refusal, ETOKEN_USE_EXHAUSTED);
    assert_int_equal(file_uses_of(id), 4);
}

static void test_no_use_is_lost_when_many_enrollments_count_at_once(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    int i;

    mint_token(id, sizeof(id), 0);

    /* An unlimited token refuses nobody, so what is under test here is the counter itself: a
     * read-modify-write outside the lock would lose updates and under-report how many agents a token
     * enrolled -- which is the only record an operator has of it */
    assert_int_equal(admitted_at_once(id, NULL), CONSUMERS);
    assert_int_equal(file_uses_of(id), CONSUMERS);

    /* The reservation each of them took is real: giving them all back returns every use */
    for (i = 0; i < CONSUMERS; i++) {
        etoken_store_release(id);
    }

    assert_int_equal(file_uses_of(id), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_a_single_use_token_admits_exactly_one_concurrent_enrollment,
                                        setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_limited_token_admits_exactly_its_max_uses,
                                        setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_no_use_is_lost_when_many_enrollments_count_at_once,
                                        setup_store, teardown_store),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}

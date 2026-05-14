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
#include <stdlib.h>
#include <pthread.h>

#include "../headers/shared.h"

#define BUFFER_LEN 64
#define N_READERS 4
#define READ_CYCLES 10000
#define WRITE_CYCLES 1000

typedef struct {
    rwlock_t * rwlock;
    char buffer[BUFFER_LEN];
} thread_args_t;

int test_rwlock_setup(void ** state) {
    *state = malloc(sizeof(rwlock_t));
    return 0;
}

int test_rwlock_teardown(void ** state) {
    free(*state);
    return 0;
}

static void * reader(thread_args_t * thread_args) {
    char target[BUFFER_LEN];

    for (int i = 0; i < READ_CYCLES; i++) {
        RWLOCK_LOCK_READ(thread_args->rwlock, {
            memcpy(target, thread_args->buffer, BUFFER_LEN);
            sched_yield();
        })
    }

    return NULL;
}

static void * writer(thread_args_t * thread_args) {
    int i = 0;

    for (int i = 0; i < WRITE_CYCLES; i++) {
        RWLOCK_LOCK_WRITE(thread_args->rwlock, {
            snprintf(thread_args->buffer, BUFFER_LEN, "%d", i);
        })

        sched_yield();
    }

    return NULL;
}

void test_rwlock_threads(void ** state) {
    pthread_t thread_writer;
    pthread_t thread_readers[N_READERS];
    thread_args_t thread_args = {
        .rwlock = *(rwlock_t **)state
    };

    rwlock_init(thread_args.rwlock);

    for (int i = 0; i < N_READERS; i++) {
        errno = pthread_create(&thread_readers[i], NULL, (void * (*)(void *))reader, (void *)&thread_args);
        assert_int_equal(errno, 0);
    }

    errno = pthread_create(&thread_writer, NULL, (void * (*)(void *))writer, (void *)&thread_args);
    assert_int_equal(errno, 0);

    if (errno != 0) {
        perror("pthread_start(writer)");
        abort();
    }

    errno = pthread_join(thread_writer, NULL);
    assert_int_equal(errno, 0);

    for (int i = 0; i < N_READERS; i++) {
        errno = pthread_join(thread_readers[i], NULL);
        assert_int_equal(errno, 0);
    }

    rwlock_destroy(thread_args.rwlock);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rwlock_threads, test_rwlock_setup, test_rwlock_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

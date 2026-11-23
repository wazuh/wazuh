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

#include "../../headers/shared.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/rules.h"

void os_remove_eventlist(EventList *list);

/* setup/teardown */



/* wraps */

static EventList *pruning_list;
static Eventinfo *published_event;
static unsigned int pruning_calls;

static void *acquire_published_event(void *arg) {
    /* The reader has already obtained the permanent sentinel before insertion. */
    EventNode *head = arg;
    pthread_mutex_lock(&head->mutex);
    EventNode *node = head->next;
    node->count++;
    pthread_mutex_unlock(&head->mutex);
    return node->event;
}

void __wrap_Free_Eventinfo(Eventinfo *lf) {
    (void)lf;
    if (pruning_list) {
        /* Pruning runs after publication, before OS_AddEvent returns. Run
         * a history reader at that point to force the problematic ordering. */
        EventNode *head = pruning_list->first_node;
        pthread_t reader;
        void *observed_event = NULL;
        assert_int_equal(pthread_create(&reader, NULL, acquire_published_event, head), 0);
        assert_int_equal(pthread_join(reader, &observed_event), 0);
        assert_ptr_equal(observed_event, published_event);
        EventNode *node = head->next;
        assert_non_null(node);
        assert_ptr_equal(published_event->node, node);
        assert_int_equal(pthread_mutex_trylock(&node->mutex), 0);
        pthread_mutex_unlock(&node->mutex);
        pruning_calls++;
    }
}

/* tests */

/* os_remove_eventlist */
void test_os_remove_eventlist_OK(void **state)
{
    (void)state;
    EventList *list;
    os_calloc(1,sizeof(EventList), list);

    os_calloc(1,sizeof(EventNode), list->first_node);

    os_remove_eventlist(list);

}

static void test_add_event_initializes_before_pruning(void **state) {
    (void)state;
    EventList *list = calloc(1, sizeof(EventList));
    Eventinfo older = {0};
    Eventinfo newest = {0};
    assert_non_null(list);
    OS_CreateEventList(1, list);
    OS_AddEvent(&older, list);
    assert_ptr_equal(list->first_node->next->event, &older);
    assert_ptr_equal(older.node, list->first_node->next);

    pruning_list = list;
    published_event = &newest;
    pruning_calls = 0;
    OS_AddEvent(&newest, list);
    pruning_list = NULL;
    published_event = NULL;

    assert_int_equal(pruning_calls, 1);
    assert_int_equal(list->_memoryused, 1);
    assert_ptr_equal(list->last_node, newest.node);
    assert_ptr_equal(list->last_added_node, newest.node);
    /* OS_AddEvent must not reset a reference obtained after publication. */
    assert_int_equal(newest.node->count, 1);
    newest.node->count--;
    pthread_mutex_destroy(&list->first_node->mutex);
    pthread_mutex_destroy(&list->event_mutex);
    os_remove_eventlist(list);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_eventlist
        cmocka_unit_test(test_os_remove_eventlist_OK),
        cmocka_unit_test(test_add_event_initializes_before_pruning),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}


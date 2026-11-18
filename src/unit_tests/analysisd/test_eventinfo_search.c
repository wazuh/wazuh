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

#include "../../headers/shared.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/rules.h"

static unsigned int clock_calls;

time_t __wrap_w_get_current_time(void) {
    /* Bound the unpatched loop without relying on wall-clock delays. */
    return 100 + ++clock_calls;
}

static void check_history(char *current_agent, char *newest_agent,
                          int context_opts, int expected_index, unsigned int expected_calls) {
    OSDecoderInfo decoder = {0};
    Eventinfo current = {.agent_id = current_agent, .decoder_info = &decoder};
    Eventinfo older = {.agent_id = "001", .decoder_info = &decoder, .generate_time = 100};
    Eventinfo newest = {.agent_id = newest_agent, .decoder_info = &decoder, .generate_time = 100};
    EventNode older_node = {.event = &older, .mutex = PTHREAD_MUTEX_INITIALIZER};
    EventNode newest_node = {.event = &newest, .mutex = PTHREAD_MUTEX_INITIALIZER, .next = &older_node};
    EventNode head = {.mutex = PTHREAD_MUTEX_INITIALIZER, .next = &newest_node};
    EventList history = {.first_node = &head, .event_mutex = PTHREAD_MUTEX_INITIALIZER};
    RuleInfo rule = {.mutex = PTHREAD_MUTEX_INITIALIZER, .timeframe = 30,
                     .level = 10, .context_opts = context_opts};
    regex_matching rule_match = {0};
    Eventinfo *expected[] = {NULL, &newest, &older};

    clock_calls = 0;
    assert_ptr_equal(Search_LastEvents(&current, &history, &rule, &rule_match), expected[expected_index]);
    assert_int_equal(clock_calls, expected_calls);
    assert_int_equal(newest_node.count, 0);
    assert_int_equal(older_node.count, 0);
    assert_int_equal(current.matched, expected_index ? rule.level : 0);

    pthread_mutex_destroy(&older_node.mutex);
    pthread_mutex_destroy(&newest_node.mutex);
    pthread_mutex_destroy(&head.mutex);
    pthread_mutex_destroy(&history.event_mutex);
    pthread_mutex_destroy(&rule.mutex);
}

static void test_different_agent_advances(void **state) {
    (void)state;
    check_history("001", "002", 0, 2, 2);
}

static void test_missing_history_agent_advances(void **state) {
    (void)state;
    check_history("001", NULL, 0, 2, 2);
}

static void test_missing_current_agent_exhausts_history(void **state) {
    (void)state;
    check_history(NULL, "002", 0, 0, 2);
}

static void test_no_matching_agent_exhausts_history(void **state) {
    (void)state;
    check_history("003", "002", 0, 0, 2);
}

static void test_same_agent_matches_newest(void **state) {
    (void)state;
    check_history("001", "001", 0, 1, 1);
}

static void test_global_frequency_matches_other_agent(void **state) {
    (void)state;
    check_history("001", "002", FIELD_GFREQUENCY, 1, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_different_agent_advances),
        cmocka_unit_test(test_missing_history_agent_advances),
        cmocka_unit_test(test_missing_current_agent_exhausts_history),
        cmocka_unit_test(test_no_matching_agent_exhausts_history),
        cmocka_unit_test(test_same_agent_matches_newest),
        cmocka_unit_test(test_global_frequency_matches_other_agent),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

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

static int teardown(void **state) {
    if (state[0]) {
        int *ids = (int*)state[0];
        os_free(ids);
    }
    return 0;
}

void test_json_parse_agents_success(void **state)
{
    cJSON *agents = cJSON_CreateArray();
    cJSON *agent1 = cJSON_CreateNumber(15);
    cJSON *agent2 = cJSON_CreateNumber(23);
    cJSON *agent3 = cJSON_CreateNumber(8);
    cJSON_AddItemToArray(agents, agent1);
    cJSON_AddItemToArray(agents, agent2);
    cJSON_AddItemToArray(agents, agent3);

    int* agent_ids = json_parse_agents(agents);

    cJSON_Delete(agents);

    state[0] = (void*)agent_ids;
    state[1] = NULL;

    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 15);
    assert_int_equal(agent_ids[1], 23);
    assert_int_equal(agent_ids[2], 8);
    assert_int_equal(agent_ids[3], -1);
}

void test_json_parse_agents_type_error(void **state)
{
    cJSON *agents = cJSON_CreateArray();
    cJSON *agent1 = cJSON_CreateNumber(15);
    cJSON *agent2 = cJSON_CreateString("23");
    cJSON *agent3 = cJSON_CreateNumber(8);
    cJSON_AddItemToArray(agents, agent1);
    cJSON_AddItemToArray(agents, agent2);
    cJSON_AddItemToArray(agents, agent3);

    int* agent_ids = json_parse_agents(agents);

    cJSON_Delete(agents);

    state[1] = NULL;

    assert_null(agent_ids);
}

void test_json_parse_agents_empty(void **state)
{
    cJSON *agents = cJSON_CreateArray();

    int* agent_ids = json_parse_agents(agents);

    cJSON_Delete(agents);

    state[0] = (void*)agent_ids;
    state[1] = NULL;

    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], -1);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        // json_parse_agents
        cmocka_unit_test_teardown(test_json_parse_agents_success, teardown),
        cmocka_unit_test_teardown(test_json_parse_agents_type_error, teardown),
        cmocka_unit_test_teardown(test_json_parse_agents_empty, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

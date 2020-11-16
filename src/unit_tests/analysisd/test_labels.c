/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../wrappers/wazuh/wazuh_db/wdb_agent_wrappers.h"

#include "../analysisd/config.h"
#include "../analysisd/labels.h"
#include "labels_op.h"

/* setup/teardown */

static int setup_labels_context(void **state) {
    labels_init();
    return OS_SUCCESS;
}

static int teardown_labels_local(void **state) {
    labels_finalize();
    return OS_SUCCESS;
}

/* tests */

void test_labels_find_manager_no_labels(void **state) {
    int sock = -1;
    char *agent_id = "000";

    wlabel_t *labels = labels_find(agent_id, &sock);

    assert_null(labels);
}

void test_labels_find_manager_with_labels(void **state) {
    int sock = -1;
    char *agent_id = "000";
    wlabel_t *manager_labels = NULL;

    // Setting the manager's labels
    os_calloc(1, sizeof(wlabel_t), manager_labels);
    Config.labels = manager_labels;

    wlabel_t *labels = labels_find(agent_id, &sock);

    assert_ptr_equal(manager_labels, labels);
    os_free(manager_labels);
}

void test_labels_find_agent_no_labels(void **state) {
    int sock = -1;
    char *agent_id = "001";

    // Requesting labels to Wazuh DB
    expect_value(__wrap_wdb_get_agent_labels, id, 1);
    will_return(__wrap_wdb_get_agent_labels, NULL);

    wlabel_t *labels = labels_find(agent_id, &sock);

    assert_null(labels);
}

void test_labels_find_agent_with_labels(void **state) {
    int sock = -1;
    char *agent_id = "001";

    // Creating a dummy set of labels
    cJSON* array = cJSON_CreateArray();
    cJSON* label1 = cJSON_CreateObject();
    cJSON_AddStringToObject(label1, "key", "#\"_system_label\"");
    cJSON_AddStringToObject(label1, "value", "system_value");
    cJSON_AddItemToArray(array, label1);
    cJSON* label2 = cJSON_CreateObject();
    cJSON_AddStringToObject(label2, "key", "!\"_hidden_label\"");
    cJSON_AddStringToObject(label2, "value", "hidden_value");
    cJSON_AddItemToArray(array, label2);
    cJSON* label3 = cJSON_CreateObject();
    cJSON_AddStringToObject(label3, "key", "\"label\"");
    cJSON_AddStringToObject(label3, "value", "value");
    cJSON_AddItemToArray(array, label3);

    // Requesting labels to Wazuh DB
    expect_value(__wrap_wdb_get_agent_labels, id, 1);
    will_return(__wrap_wdb_get_agent_labels, array);

    wlabel_t *labels = labels_find(agent_id, &sock);

    assert_non_null(labels);
    assert_string_equal("system_value", labels_get(labels, "_system_label"));
    assert_string_equal("hidden_value", labels_get(labels, "_hidden_label"));
    assert_string_equal("value", labels_get(labels, "label"));
    labels_free(labels);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* dispatch_send_local */
        cmocka_unit_test_setup_teardown(test_labels_find_manager_no_labels, setup_labels_context, teardown_labels_local),
        cmocka_unit_test_setup_teardown(test_labels_find_manager_with_labels, setup_labels_context, teardown_labels_local),
        cmocka_unit_test_setup_teardown(test_labels_find_agent_no_labels, setup_labels_context, teardown_labels_local),
        cmocka_unit_test_setup_teardown(test_labels_find_agent_with_labels, setup_labels_context, teardown_labels_local)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

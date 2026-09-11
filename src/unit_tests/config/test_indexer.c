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

#include "config.h"
#include "indexer-config.h"
#include "../../external/cJSON/cJSON.h"

static int setup_test_read(void **state) {
    (void) state;
    indexer_config = NULL;
    return 0;
}

static int teardown_test_read(void **state) {
    (void) state;
    if (indexer_config) {
        cJSON_Delete(indexer_config);
        indexer_config = NULL;
    }
    return 0;
}

/* Read_Indexer_JSON: the effective `indexer` section of etc/wazuh-manager.conf becomes indexer_config; an
 * empty host list (the schema default for an absent section) or a NULL section leaves it NULL. */

void test_read_indexer_json_sets_global_config(void **state) {
    (void) state;
    const char *section_str = "{\"hosts\":[\"https://10.0.0.1:9200\"],\"ssl\":{\"certificate_authorities\":[\"ca.pem\"],\"certificate\":\"c.pem\",\"key\":\"k.pem\"}}";
    cJSON *section = cJSON_Parse(section_str);

    assert_int_equal(Read_Indexer_JSON(section), OS_SUCCESS);
    cJSON_Delete(section);

    assert_non_null(indexer_config);
    char *json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, section_str);
    cJSON_free(json_result);
}

void test_read_indexer_json_empty_hosts_is_null(void **state) {
    (void) state;
    cJSON *section = cJSON_Parse("{\"hosts\":[]}");

    assert_int_equal(Read_Indexer_JSON(section), OS_SUCCESS);
    cJSON_Delete(section);

    assert_null(indexer_config);
}

void test_read_indexer_json_null_section_replaces_previous(void **state) {
    (void) state;
    cJSON *section = cJSON_Parse("{\"hosts\":[\"https://10.0.0.1:9200\"]}");

    assert_int_equal(Read_Indexer_JSON(section), OS_SUCCESS);
    cJSON_Delete(section);
    assert_non_null(indexer_config);

    assert_int_equal(Read_Indexer_JSON(NULL), OS_SUCCESS);
    assert_null(indexer_config);
}

void test_read_indexer_json_ssl_optional(void **state) {
    (void) state;
    const char *section_str = "{\"hosts\":[\"https://10.0.0.1:9200\",\"https://10.0.0.2:9200\"]}";
    cJSON *section = cJSON_Parse(section_str);

    assert_int_equal(Read_Indexer_JSON(section), OS_SUCCESS);
    cJSON_Delete(section);

    assert_non_null(indexer_config);
    assert_null(cJSON_GetObjectItem(indexer_config, "ssl"));
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(indexer_config, "hosts")), 2);
}

int main(void) {
    const struct CMUnitTest tests_configuration[] = {
        cmocka_unit_test_setup_teardown(test_read_indexer_json_sets_global_config, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_indexer_json_empty_hosts_is_null, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_indexer_json_null_section_replaces_previous, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_indexer_json_ssl_optional, setup_test_read, teardown_test_read),
    };
    return cmocka_run_group_tests(tests_configuration, NULL, NULL);
}

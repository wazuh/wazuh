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
#include <string.h>

#include "shared.h"
#include "../../os_maild/maild.h"

#define BODY_SIZE_INVARIANT (OS_MAXSTR - 3)

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

static void test_printtable_final_node(void **state) {
    char logs[OS_MAXSTR + 1] = "";
    char tab[256] = "\t";
    size_t body_size = BODY_SIZE_INVARIANT;
    cJSON *al_json = cJSON_Parse("{\"text\":\"Hello world.\"}");

    PrintTable(al_json, logs, &body_size, tab, 2);
    cJSON_Delete(al_json);

    assert_int_equal(strlen(logs) + body_size, BODY_SIZE_INVARIANT);
}

static void test_printtable_array(void **state) {
    char logs[OS_MAXSTR + 1] = "";
    char tab[256] = "\t";
    size_t body_size = BODY_SIZE_INVARIANT;
    cJSON *al_json = cJSON_Parse("{\"array\":[1,2,3]}");

    PrintTable(al_json, logs, &body_size, tab, 2);
    cJSON_Delete(al_json);

    assert_int_equal(strlen(logs) + body_size, BODY_SIZE_INVARIANT);
}

static void test_printtable_nested(void **state) {
    char logs[OS_MAXSTR + 1] = "";
    char tab[256] = "\t";
    size_t body_size = BODY_SIZE_INVARIANT;
    cJSON *al_json = cJSON_Parse("{\"data\":{\"text\":\"Hello world.\"}}");

    PrintTable(al_json, logs, &body_size, tab, 2);
    cJSON_Delete(al_json);

    assert_int_equal(strlen(logs) + body_size, BODY_SIZE_INVARIANT);
}

static void test_printtable_nested_next(void **state) {
    char logs[OS_MAXSTR + 1] = "";
    char tab[256] = "\t";
    size_t body_size = BODY_SIZE_INVARIANT;
    cJSON *al_json = cJSON_Parse("{\"nothing\":{},\"data\":{\"text\":\"Hello world.\"}}");

    PrintTable(al_json, logs, &body_size, tab, 2);
    cJSON_Delete(al_json);

    assert_int_equal(strlen(logs) + body_size, BODY_SIZE_INVARIANT);
}

static void test_printtable_max_tabs(void **state) {
    char logs[OS_MAXSTR + 1] = "";
    char tab[256] = "\t";
    size_t body_size = BODY_SIZE_INVARIANT;
    cJSON *al_json = cJSON_Parse("{\"first\":{\"second\":{\"third\":{\"fourth\":{\"fiveth\":{\"sixth-a\":\"Hello\"},\"sixth-b\":\"World\"}}}}}");

    PrintTable(al_json, logs, &body_size, tab, 2);
    cJSON_Delete(al_json);

    assert_int_equal(strlen(logs) + body_size, BODY_SIZE_INVARIANT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_printtable_final_node),
        cmocka_unit_test(test_printtable_array),
        cmocka_unit_test(test_printtable_nested),
        cmocka_unit_test(test_printtable_nested_next),
        cmocka_unit_test(test_printtable_max_tabs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

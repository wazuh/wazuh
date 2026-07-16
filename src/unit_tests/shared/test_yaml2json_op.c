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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../headers/shared.h"
#include "../../headers/yaml2json.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

static char * write_temp_yaml(const char * content) {
    char * path;
    os_strdup("/tmp/test_yaml2json_XXXXXX", path);

    int fd = mkstemp(path);
    assert_true(fd >= 0);

    FILE * fp = fdopen(fd, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);

    return path;
}

static int teardown_temp_file(void ** state) {
    char * path = *state;
    unlink(path);
    os_free(path);
    return 0;
}

/* A normal, small SCA-like policy must still convert successfully. */
static void test_yaml2json_valid_policy(void ** state) {
    char * path = write_temp_yaml(
        "policy:\n"
        "  id: test_policy\n"
        "  file: 'test_policy.yml'\n"
        "  name: Test policy\n"
        "checks:\n"
        "  - id: 1\n"
        "    title: \"Test check\"\n"
        "    condition: all\n"
        "    rules:\n"
        "      - 'f:/etc/passwd'\n"
    );
    *state = path;

    yaml_document_t document;
    assert_int_equal(yaml_parse_file(path, &document), 0);

    cJSON * object = yaml2json(&document, 1);
    assert_non_null(object);

    cJSON * policy = cJSON_GetObjectItem(object, "policy");
    assert_non_null(policy);
    assert_string_equal(cJSON_GetObjectItem(policy, "id")->valuestring, "test_policy");

    cJSON * checks = cJSON_GetObjectItem(object, "checks");
    assert_int_equal(cJSON_GetArraySize(checks), 1);

    cJSON_Delete(object);
    yaml_document_delete(&document);
}

/* Nested anchors/aliases must not be allowed to expand into an
 * unbounded number of JSON nodes. */
static void test_yaml2json_alias_expansion_rejected(void ** state) {
    char * path = write_temp_yaml(
        "policy:\n"
        "  id: expansion_test\n"
        "checks:\n"
        "  - id: 1\n"
        "    rules: &a [\"f:/etc/passwd\"]\n"
        "  - id: 2\n"
        "    rules: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
        "  - id: 3\n"
        "    rules: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
        "  - id: 4\n"
        "    rules: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
        "  - id: 5\n"
        "    rules: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]\n"
        "  - id: 6\n"
        "    rules: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e, *e]\n"
    );
    *state = path;

    yaml_document_t document;
    assert_int_equal(yaml_parse_file(path, &document), 0);

    expect_string(__wrap__mwarn, formatted_msg,
                  "YAML document exceeds the maximum number of nodes (100000). Possible alias expansion abuse.");

    cJSON * object = yaml2json(&document, 1);
    assert_null(object);

    yaml_document_delete(&document);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_yaml2json_valid_policy, teardown_temp_file),
        cmocka_unit_test_teardown(test_yaml2json_alias_expansion_rejected, teardown_temp_file),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

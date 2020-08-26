#include "../headers/shared.h"
#include "tap.h"

int test_search_and_replace(){

    int i;
    const char *tests[][4] = {
        {"testMe", "nomatch", "", "testMe"},
        {"test me", "ME", "me", "test me"},
        {"test me", "me", "ME", "test ME"},
        {"testMe", "test", "Tested", "TestedMe"},
        {"Metest", "test", "Tested", "MeTested"},
        {"A B CTeStD E F", "TeSt", "tEsT", "A B CtEsTD E F"},
        {"TeStA B CTeStD E F", "TeSt", "tEsT", "tEsTA B CtEsTD E F"},
        {"TeSt TeStA B CTeStD E F", "TeSt", "tEsT", "tEsT tEsTA B CtEsTD E F"},
        {"A B CTeStD E FTeSt", "TeSt", "tEsT", "A B CtEsTD E FtEsT"},
        {"A B CTeStD E FTeSt TeSt", "TeSt", "tEsT", "A B CtEsTD E FtEsT tEsT"},
        {"TeSt++ TeSt++A B CTeSt++D E F", "TeSt++", "tEsT", "tEsT tEsTA B CtEsTD E F"},
        {"A B CTeStD E FTeSt TeSt", "TeSt", "tEsT++", "A B CtEsT++D E FtEsT++ tEsT++"},
        {NULL, NULL, NULL, NULL}
    };

    for (i = 0; tests[i][0] != NULL ; i++) {
        char *result = searchAndReplace(tests[i][0], tests[i][1], tests[i][2]);
        w_assert_str_eq(result, tests[i][3]);
        free(result);
    }
    return 1;
}

int test_utf8_random(bool replacement) {
    size_t i;
    const size_t LENGTH = 4096;
    char buffer[LENGTH];

    randombytes(buffer, LENGTH - 1);

    /* Avoid zeroes */

    for (i = 0; i < LENGTH - 1; i++) {
        buffer[i] = buffer[i] ? buffer[i] : '0';
    }

    buffer[LENGTH - 1] = '\0';

    char * copy = w_utf8_filter(buffer, replacement);
    int r = w_utf8_valid(copy);
    free(copy);

    return r;
}

static int compare(const struct statfs * statfs) {
    for (int i = 0; network_file_systems[i].name; i++) {
        if (network_file_systems[i].f_type == statfs->f_type) {
            return 1;
        }
    }

    for (int i = 0; skip_file_systems[i].name; i++) {
        if (skip_file_systems[i].f_type == statfs->f_type) {
            return 1;
        }
    }

    return 0;
}

static int test_fs_magic() {
    struct statfs statfs = {.f_type = 0x6969};
    w_assert_int_eq(compare(&statfs), 1);

    statfs.f_type = 0xFF534D42;
    w_assert_int_eq(compare(&statfs), 1);

    statfs.f_type = 0x9123683E;
    w_assert_int_eq(compare(&statfs), 1);

    statfs.f_type = 0x61756673;
    w_assert_int_eq(compare(&statfs), 1);

    statfs.f_type = 0x794c7630;
    w_assert_int_eq(compare(&statfs), 1);

    return 1;
}

int test_strnspn_escaped() {
    w_assert_uint_eq(strcspn_escaped("ABC\\D ", ' '), 5);
    w_assert_uint_eq(strcspn_escaped("ABC\\ D", ' '), 6);
    w_assert_uint_eq(strcspn_escaped("ABCD\\", ' '), 5);
    w_assert_uint_eq(strcspn_escaped("ABCDE \\ ", ' '), 5);
    w_assert_uint_eq(strcspn_escaped("ABCDE\\\\ F", ' '), 7);
    w_assert_uint_eq(strcspn_escaped("ABCDE\\\\", ' '), 7);
    w_assert_uint_eq(strcspn_escaped("ABC\\ D E", ' '), 6);
    w_assert_uint_eq(strcspn_escaped("ABCDE", ' '), 5);

    return 1;
}

int test_json_escape() {
    const char * INPUTS[] = { "\b\tHello \n\f\r \"World\".\\", "Hello\b\t \n\f\r \"World\"\\.", NULL };
    const char * EXPECTED_OUTPUTS[] = { "\\b\\tHello \\n\\f\\r \\\"World\\\".\\\\", "Hello\\b\\t \\n\\f\\r \\\"World\\\"\\\\.", NULL };
    int i;

    for (i = 0; INPUTS[i] != NULL; i++) {
        char * output = wstr_escape_json(INPUTS[i]);
        int cmp = strcmp(output, EXPECTED_OUTPUTS[i]);
        free(output);

        if (cmp != 0) {
            return 0;
        }
    }

    return 1;
}

int test_json_unescape() {
    const char * INPUTS[] = { "\\b\\tHello \\n\\f\\r \\\"World\\\".\\\\", "Hello\\b\\t \\n\\f\\r \\\"World\\\"\\\\.", "Hello \\World", "Hello World\\", NULL };
    const char * EXPECTED_OUTPUTS[] = { "\b\tHello \n\f\r \"World\".\\", "Hello\b\t \n\f\r \"World\"\\.", "Hello \\World", "Hello World\\", NULL };
    int i;

    for (i = 0; INPUTS[i] != NULL; i++) {
        char * output = wstr_unescape_json(INPUTS[i]);
        int cmp = strcmp(output, EXPECTED_OUTPUTS[i]);
        free(output);

        if (cmp != 0) {
            return 0;
        }
    }

    return 1;
}

int test_log_builder() {
    const char * PATTERN = "location: $(location), log: $(log), escaped: $(json_escaped_log)";
    const char * LOG = "Hello \"World\"";
    const char * LOCATION = "test";
    const char * EXPECTED_OUTPUT = "location: test, log: Hello \"World\", escaped: Hello \\\"World\\\"";

    int retval = 1;
    log_builder_t * builder = log_builder_init(false);

    if (builder == NULL) {
        return 0;
    }

    char * output = log_builder_build(builder, PATTERN, LOG, LOCATION);

    if (strcmp(output, EXPECTED_OUTPUT) != 0) {
        retval = 0;
    }

    free(output);
    log_builder_destroy(builder);
    return retval;
}

int test_get_file_content() {
    int max_size = 100;
    const char * expected = "{\n"
                            "    \"test\":[\n"
                            "        {\n"
                            "            \"test_name\":\"Test1\",\n"
                            "            \"test_number\":1\n"
                            "        }, {\n"
                            "            \"test_name\":\"Test2\",\n"
                            "            \"test_number\":2\n"
                            "        }, {\n"
                            "            \"test_name\":\"Test3\",\n"
                            "            \"test_number\":3\n"
                            "        }\n"
                            "    ]\n"
                            "}\n";

    char * content;

    // Test NULL path
    if (content = w_get_file_content(NULL, max_size), content != NULL) {
        return 0;
    }

    // Test invalid path
    if (content = w_get_file_content("./tests/invalid_path", max_size), content != NULL) {
        return 0;
    }

    // Test file size exceeds max size allowed
    if (content = w_get_file_content("./tests/test_file.json", max_size), content != NULL) {
        return 0;
    }

    max_size = 300;

    // Test file content
    if (content = w_get_file_content("./tests/test_file.json", max_size), content == NULL) {
        return 0;
    }

    w_assert_str_eq(content, expected);
    free(content);

    return 1;
}

int main(void) {
    printf("\n\n   STARTING TEST - OS_SHARED   \n\n");

    // Search and replace strings test
    TAP_TEST_MSG(test_search_and_replace(), "Search and replace strings test.");

    /* Test UTF-8 string operations */
    TAP_TEST_MSG(test_utf8_random(true), "Filter a random string into UTF-8 with character replacement.");

    /* Test UTF-8 string operations */
    TAP_TEST_MSG(test_utf8_random(false), "Filter a random string into UTF-8 without character replacement.");

    /* Test filesystem magic code searching */
    TAP_TEST_MSG(test_fs_magic(), "Filesystem magic code searching.");

    /* Test strnspn_escaped function */
    TAP_TEST_MSG(test_strnspn_escaped(), "Check return values for stnspn_escaped.");

    /* Test reserved JSON character escaping */
    TAP_TEST_MSG(test_json_escape(), "Escape reserved JSON characters.");

    /* Test reserved JSON character unescaping */
    TAP_TEST_MSG(test_json_unescape(), "Unescape reserved JSON characters.");

    /* Test log builder */
    TAP_TEST_MSG(test_log_builder(), "Test log builder.");

    /* Test get_file_content function */
    TAP_TEST_MSG(test_get_file_content(), "Get the content of a file.");

    TAP_PLAN;
    int r = tap_summary();
    printf("\n   ENDING TEST  - OS_SHARED   \n\n");
    return r;
}

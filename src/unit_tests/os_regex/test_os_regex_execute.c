
#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../../external/cJSON/cJSON.h"
#include "../../os_regex/os_regex.h"
#include "../../os_regex/os_regex_internal.h"
#include "../wrappers/common.h"

#ifndef JSON_PATH_TEST
#define JSON_PATH_TEST ""
#endif

// Helpers
/**
 * @brief Test status result
 */
struct _result_test {
    unsigned int expected_failed_tests;      ///< Expected failed tests count
    unsigned int tests_errors_count;         ///< Tests errors count
    unsigned int failed_tests_count;         ///< Failed tests count
    unsigned int executed_tests_suite_count; ///< Executed tests suit count
    unsigned int executed_unit_test_count;   ///< Executed tests suit count
    unsigned int skipped_unit_test_count;    ///< Skipped tests count
} result;

/**
 * @brief Unit test definition for OS_Regex_Execute()
 */
typedef struct test_case_parameters {
    char * description;      ///< Test description
    bool ignore_result;      ///< Ignore result (for tests with known failures)
    bool debug;              ///< Debug UT, print all information on error
    bool skip;               ///< Skip test
    char * pattern;          ///< Regex pattern
    char * log;              ///< Log to match with the pattern
    char * end_match;        ///< Expected end match string (NULL if not matched)
    char ** captured_groups; ///< Expected captured groups (NULL if not captured)
} test_case_parameters;

typedef test_case_parameters ** batch_test;

/**
 * @brief Print the test's configuration
 *
 * @param test Contains the test configuration
 */
static inline void print_os_regex_test_parameters(const test_case_parameters * test) {
    printf("*********************************\n");
    printf("Test description:\n");
    printf("\t%s\n", (test->description != NULL) ? test->description : "This unit test has no description.");
    printf("\n");
    printf("Is the result ignored? %s\n", (test->ignore_result) ? "yes" : "no");
    printf("\n");
    printf("Pattern:\n");
    printf("\t\"%s\"\n", test->pattern);
    printf("\n");
    printf("Log:\n");
    printf("\t\"%s\"\n", test->log);
    printf("\n");
    printf("Expected end matching string:\n");
    printf("\t\"%s\"\n", (test->end_match != NULL) ? test->end_match : "");
    printf("\n");
    printf("Expected capture groups:\n");
    if (test->captured_groups != NULL) {
        for (int i = 0; *(test->captured_groups + i) != NULL; i++) {
            printf("\t\"%s\"\n", *(test->captured_groups + i));
        }
    }
    printf("\n");
    printf("*********************************\n");
}

/**
 * @brief Execute a test case for OS_Regex_Execute()*
 * @param test_case Test case definition
 * @param matching_result Pointer to the matching_result structure to fill with the results of the match
 */
void exec_test_case(test_case_parameters * test_case, regex_matching * matching_result) {

    if(test_case->skip) {
        if(test_case->debug) {
            printf("Test case skipped: %s\n", test_case->description != NULL ? test_case->description : "");
        }
        result.skipped_unit_test_count++;
        return;
    }
    result.executed_unit_test_count++;

    bool test_failed = false;
    bool print_on_error = (test_case->debug || !test_case->ignore_result);

    // Compile & match
    OSRegex * regex = calloc(1, sizeof(OSRegex));
    const char * match_retval = NULL;

    bool compile_regex = OSRegex_Compile(test_case->pattern, regex, OS_RETURN_SUBSTRING);

    if(!compile_regex) {

        result.failed_tests_count++;
        result.tests_errors_count++;

        if (print_on_error) {
            print_os_regex_test_parameters(test_case);
            printf("Syntax error on regex: '%s': %d.\n", test_case->pattern, regex->error);
        }
        // Only stop if the test is not ignored
        if (!test_case->ignore_result) {
            assert_false(true);
        }
        free(regex);
        return;
    }

    // Check results
    // Check match result
    match_retval = OSRegex_Execute_ex(test_case->log, regex, matching_result);

    if ((test_case->end_match == NULL && match_retval != NULL) ||
        (test_case->end_match != NULL && match_retval == NULL)) {

        test_failed = true;
        result.failed_tests_count++;
        result.tests_errors_count++;

        if (print_on_error) {
            print_os_regex_test_parameters(test_case);
            if (match_retval != NULL) {
                printf("Error: regex '%s' should not match '%s' but it does.\n", test_case->pattern, test_case->log);
            } else {
                printf("Error: regex '%s' should match '%s' but it doesn't.\n", test_case->pattern, test_case->log);
            }
        }
        // Only stop if the test is not ignored
        if (!test_case->ignore_result) {
            assert_false(true);
        }
    }

    // If there is nothing to match (match_retval == NULL) then we are done
    if (match_retval == NULL || test_case->end_match == NULL) {
        OSRegex_FreePattern(regex);
        free(regex);
        return;
    }

    // Check if the last character matched is equal to the expected one
    bool strcmp_matched = (strcmp(match_retval, test_case->end_match) == 0);
    if (!strcmp_matched) {

        result.tests_errors_count++;

        if (!test_failed) {
            test_failed = true;
            result.failed_tests_count++;

            if(print_on_error) {
                print_os_regex_test_parameters(test_case);
            }
        }

        if (print_on_error) {
            printf("DEBUG (ERROR): the last matched remanent string is '%s', but the expected one is '%s'.\n", match_retval,
                   test_case->end_match);
        }
        // Only stop if the test is not ignored
        if (!test_case->ignore_result) {
            assert_false(true);
        }
    }

    // Check the captured groups
    int i = 0;
    do {
        const char * expected_str = test_case->captured_groups != NULL ? test_case->captured_groups[i] : NULL;
        const char * actual_str = matching_result->sub_strings[i];

        // All capture groups must be compared, that is, logical XOR
        int parity = (!(expected_str == NULL) == !(actual_str == NULL));
        if (!parity) {

            result.tests_errors_count++;

            if (!test_failed) {
                test_failed = true;
                result.failed_tests_count++;

                if(print_on_error) {
                    print_os_regex_test_parameters(test_case);
                }
            }

            if (print_on_error) {
                if (expected_str != NULL) {
                    printf("The group: '%s' cannot be found\n", expected_str);
                } else if (actual_str != NULL) {
                    printf("The group: '%s' was found, but not compared\n", actual_str);
                }
            }

            // Stop if the test is not ignored
            if (!test_case->ignore_result) {
                assert_false(true);
            } else {
                break; // stop checking the groups, no have groups to compare
            }
        }

        // Check the captured group
        if (expected_str != NULL) {
            bool strcmp_group_matched = (strcmp(expected_str, actual_str) == 0);
            if (!strcmp_group_matched) {

                result.tests_errors_count++;

                if (!test_failed) {
                    test_failed = true;
                    result.failed_tests_count++;

                    if(print_on_error) {
                        print_os_regex_test_parameters(test_case);
                    }
                }

                if (print_on_error) {
                    printf("DEBUG (ERROR): the expected group is '%s', but the captured one is '%s'.\n", expected_str,
                           actual_str);
                }

                // Only stop if the test is not ignored
                if (!test_case->ignore_result) {
                    assert_false(true);
                }
            }
        } else {
            break;
        }
    } while (++i, test_case->captured_groups[i]);

    OSRegex_FreePattern(regex);
    free(regex);
}

// Load test cases from a JSON file
cJSON * readFile() {

    // Open the file
    FILE * fp = fopen(JSON_PATH_TEST, "r");
    if (fp == NULL) {
        printf("Error: cannot open file  '%s'\n", JSON_PATH_TEST);
    }
    assert_non_null(fp);

    // Calculate the file size for allocation of the buffer
    assert_int_equal(fseek(fp, 0, SEEK_END), 0);
    const size_t buffer_size = ftell(fp) + 1;
    assert_int_equal(fseek(fp, 0, SEEK_SET), 0);

    char * raw_json_file = calloc(buffer_size, sizeof(char));

    // Load test suite
    size_t read_bytes = fread(raw_json_file, sizeof(char), buffer_size, fp);
    if (read_bytes == 0) {
        printf("Error: cannot read file  '%s'\n", JSON_PATH_TEST);
    }
    fclose(fp);
    assert_int_not_equal(read_bytes, 0);

    // Parse the file
    cJSON * json_file = cJSON_Parse(raw_json_file);
    if (json_file == NULL) {
        printf("Error: cannot parse file  '%s'\n", JSON_PATH_TEST);
    }
    assert_non_null(json_file);

    free(raw_json_file);
    return json_file;
}

/**
 * @brief Load a test case from a JSON object
 *
 * JSON oject structure:
 * {
 *  "pattern": "regex pattern",
 *  "log": "log to match with the pattern",
 *  "end_match": "expected end match string (NULL if not matched)",
 *  "captured_groups": ["captured group 1", "captured group 2", ...]
 * }
 * @param json_test_case JSON object containing the test case
 * @return Test case definition
 */

test_case_parameters * load_test_case(cJSON * json_test_case) {

    // create a test_case_parameters
    test_case_parameters * test_case = calloc(1, sizeof(test_case_parameters));
    assert_non_null(test_case);

    // Description
    cJSON * j_description = cJSON_GetObjectItemCaseSensitive(json_test_case, "description");
    if (j_description != NULL) {
        assert_true(cJSON_IsString(j_description));
        test_case->description = strdup(cJSON_GetStringValue(j_description));
    }

    // Ignore result
    cJSON * j_ignore_result = cJSON_GetObjectItemCaseSensitive(json_test_case, "ignore_result");
    if (j_ignore_result != NULL) {
        assert_true(cJSON_IsBool(j_ignore_result));
        test_case->ignore_result = cJSON_IsTrue(j_ignore_result);
    }

    // Load debug mode
    cJSON * j_debug = cJSON_GetObjectItemCaseSensitive(json_test_case, "debug");
    if (j_debug != NULL) {
        assert_true(cJSON_IsBool(j_debug));
        test_case->debug = cJSON_IsTrue(j_debug);
    }

    // Load skip
    cJSON * j_skip = cJSON_GetObjectItemCaseSensitive(json_test_case, "skip_test");
    if (j_skip != NULL) {
        assert_true(cJSON_IsBool(j_skip));
        test_case->skip = cJSON_IsTrue(j_skip);
    }

    // pattern
    cJSON * j_pattern = cJSON_GetObjectItemCaseSensitive(json_test_case, "pattern");
    assert_non_null(j_pattern);
    // The pattern is mandatory and must be a string
    assert_true(cJSON_IsString(j_pattern));
    test_case->pattern = strdup(cJSON_GetStringValue(j_pattern));

    // log
    cJSON * j_log = cJSON_GetObjectItemCaseSensitive(json_test_case, "log");
    assert_non_null(j_log);
    // The log is mandatory and must be a string
    assert_true(cJSON_IsString(j_log));
    test_case->log = strdup(cJSON_GetStringValue(j_log));

    // end_match
    cJSON * j_end_match = cJSON_GetObjectItemCaseSensitive(json_test_case, "end_match");
    assert_non_null(j_end_match);
    // The end_match is mandatory and must be a string or null
    if (cJSON_IsNull(j_end_match)) {
        test_case->end_match = NULL;
    } else {
        assert_true(cJSON_IsString(j_end_match));
        test_case->end_match = strdup(cJSON_GetStringValue(j_end_match));
    }

    // captured_groups
    cJSON * j_captured_groups = cJSON_GetObjectItemCaseSensitive(json_test_case, "captured_groups");
    assert_non_null(j_captured_groups);
    assert_true(cJSON_IsArray(j_captured_groups));
    int i = 0;
    do {

        cJSON * j_captured_group = cJSON_GetArrayItem(j_captured_groups, i);
        if (j_captured_group == NULL) {
            break;
        }

        assert_true(cJSON_IsString(j_captured_group));
        test_case->captured_groups = realloc(test_case->captured_groups, sizeof(char *) * (i + 2));

        test_case->captured_groups[i] = strdup(cJSON_GetStringValue(j_captured_group));
        test_case->captured_groups[i + 1] = NULL;

    } while (++i);

    return test_case;
}

/**
 * @brief Free a test case
 * @param test_case Test case to free
 */
void free_test_case_parameters(test_case_parameters * test_case) {

    if (test_case->description != NULL) {
        free(test_case->description);
    }
    free(test_case->pattern);
    free(test_case->log);
    if (test_case->end_match != NULL) {
        free(test_case->end_match);
    }
    if (test_case->captured_groups != NULL) {
        for (int i = 0; test_case->captured_groups[i] != NULL; i++) {
            free(test_case->captured_groups[i]);
        }
        free(test_case->captured_groups);
    }
    free(test_case);
}

/**
 * @brief Load batch of test from a JSON array
 *
 * @param json_batch array of batch test
 * @return test_case_parameters** batch of test
 */
batch_test load_batch_test_case(cJSON * json_batch) {

    batch_test batch = NULL;

    int i = 0; // test index
    while (true) {
        batch = realloc(batch, sizeof(test_case_parameters) * (i + 2));
        batch[i] = NULL;
        batch[i + 1] = NULL;

        cJSON * json_test_case = cJSON_GetArrayItem(json_batch, i);
        if (json_test_case == NULL) {
            break;
        }
        assert_true(cJSON_IsObject(json_test_case));
        batch[i] = load_test_case(json_test_case);
        assert_non_null(batch[i]);
        i++;
    };
    return batch;
}

/**
 * @brief Free a batch of test
 * @param batch Batch of test to free
 */
void free_batch_test_case(batch_test batch) {
    for (int i = 0; batch[i] != NULL; i++) {
        free_test_case_parameters(batch[i]);
    }
    free(batch);
}

/**
 * @brief Execute a batch of test, all batch test shared the same regex_matching structure
 *
 * @param batch array of test case
 */
void exectute_batch_test(batch_test batch) {
    regex_matching regex_match = {0};
    // Execute a batch of test cases
    for (int case_id = 0; batch[case_id] != NULL; case_id++) {
        exec_test_case(batch[case_id], &regex_match);
    }
    OSRegex_free_regex_matching(&regex_match);
}
/*
 * Test definitions
 * Each batch of test, define a group of unit tests. This unit test shared the regex_matching structure.
 * This structure is used to store the results of the match.
 *
 * All batch test should be register in the test_suite array;
 */

void test_regex_execute_regex_matching(void ** state) {

    // CMocka configuration
    (void) state;
    unsigned char test = 0;

    /*
    result.expected_failed_tests is a double check.
    This number must be changed manually when:
        - Failed tests are added (Increases)
        - Bugs are fixed (Decreases)
    */
    result.expected_failed_tests = 211; ///< Number of tests that ignore the results and fail.

    // Load tests suite
    cJSON * json_file = readFile();
    assert_true(cJSON_IsArray(json_file));

    // Load the suite of tests
    cJSON * json_suite = cJSON_GetArrayItem(json_file, 0);
    for (int i = 0; json_suite != NULL; json_suite = cJSON_GetArrayItem(json_file, ++i)) {
        // Get test suite
        // Te test suite must be an array
        assert_true(cJSON_IsObject(json_suite));

        // Every test suite must have a description
        cJSON * j_description = cJSON_GetObjectItemCaseSensitive(json_suite, "description");
        if (j_description == NULL) {
            printf("Test suite %d has no description\n", i);
        }
        assert_non_null(j_description);
        assert_true(cJSON_IsString(j_description));

        // Get batch of test
        cJSON * j_batch = cJSON_GetObjectItemCaseSensitive(json_suite, "batch_test");
        if (j_batch == NULL) {
            printf("Test suite %d has no batch of test\n", i);
        }
        assert_non_null(j_batch);
        assert_true(cJSON_IsArray(j_batch));

        batch_test batch = load_batch_test_case(j_batch);
        assert_non_null(batch);

        // Exceute the batch of test
        printf("[ OS_REGEX ] Testing suite: %s\n", j_description->valuestring);
        exectute_batch_test(batch);
        free_batch_test_case(batch);
        result.executed_tests_suite_count++;
    }

    cJSON_Delete(json_file);

    // Print result test
    printf("[ OS_REGEX ] --------------------------------\n");
    // Total number of suites executed
    printf("[ OS_REGEX ] >>> Amount of executed suites: %d\n", result.executed_tests_suite_count);
    // Total number of unit tests
    printf("[ OS_REGEX ] >>> Amount of unit tests: %d\n", result.executed_unit_test_count + result.skipped_unit_test_count);
    // Total number of unit tests executed
    printf("[ OS_REGEX ] >>> Amount of executed unit tests: %d\n", result.executed_unit_test_count);
    // Total number of unit tests that skipped
    printf("[ OS_REGEX ] >>> Amount of skipped unit tests: %d\n", result.skipped_unit_test_count);
    // Total number of unit tests that failed
    printf("[ OS_REGEX ] >>> Amount of failed unit tests: %d\n", result.failed_tests_count);
    // Total number of errors found
    printf("[ OS_REGEX ] >>> Amount of errors found: %d\n", result.tests_errors_count);
    //
    printf("[ OS_REGEX ] --------------------------------\n");

    assert_int_equal(result.expected_failed_tests, result.failed_tests_count);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_regex_execute_regex_matching),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

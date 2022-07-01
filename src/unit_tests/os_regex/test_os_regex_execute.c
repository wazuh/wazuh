
#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "../../os_regex/os_regex.h"
#include "../../os_regex/os_regex_internal.h"
#include "../wrappers/common.h"

// Helpers
/**
 * @brief Unit test definition for OS_Regex_Execute()
 */
typedef struct test_case_parameters {
    const char * pattern;          ///< Regex pattern
    const char * log;              ///< Log to match with the pattern
    const char * end_match;        ///< Expected end match string (NULL if not matched)
    const char ** captured_groups; ///< Expected captured groups (NULL if not captured)
} test_case_parameters;

/**
 * @brief Execute a test case for OS_Regex_Execute()*
 * @param test_case Test case definition
 * @param matching_result Pointer to the matching_result structure to fill with the results of the match
 */
void exec_test_case(test_case_parameters * test_case, regex_matching * matching_result) {

    // Compile & match
    OSRegex * regex = calloc(1, sizeof(OSRegex));
    const char * match_retval = NULL;

    OSRegex_Compile(test_case->pattern, regex, OS_RETURN_SUBSTRING);
    match_retval = OSRegex_Execute_ex(test_case->log, regex, matching_result);

    // Check results
    // The regex should match
    if (match_retval == NULL) {
        printf("Error: regex '%s' should match '%s'\n", test_case->pattern, test_case->log);
    }
    assert_non_null(match_retval);

    // If the end_match field is defined on the test, then it needs to be checked.
    // Otherwise, it is because there is a know bug and so it make no sense to check it.
    if (test_case->end_match != NULL) {
        assert_string_equal(match_retval, test_case->end_match);
    }

    // Check the captured groups
    int i = 0;
    do {
        const char * exp_str = test_case->captured_groups != NULL ? test_case->captured_groups[i] : NULL;
        const char * act_str = matching_result->sub_strings[i];

        // All capture groups must be compared, that is, logical XOR
        int parity = (!(exp_str == NULL) == !(act_str == NULL));

        if (!parity) {
            // Only print on fail test case
            // Without this print is really hard to found the buggy line
            printf("Fail on regex: '%s', with log: '%s'\n", test_case->pattern, test_case->log);
            if (exp_str != NULL) {
                printf("The group: '%s' cannot be found\n", exp_str);
            } else if (act_str != NULL) {
                printf("The group: '%s' was found, but not compared\n", act_str);
            }
        }
        assert_true(parity);

        // Check the captured groups
        if (exp_str != NULL) {
            assert_string_equal(exp_str, act_str);
        } else {
            break;
        }
    } while (++i, test_case->captured_groups[i]);

    OSRegex_FreePattern(regex);
    free(regex);
}

/*
 * Test definitions
 * Each batch of test, define a group of unit tests. This unit test shared the regex_matching structure.
 * This structure is used to store the results of the match.
 * 
 * All batch test should be register in the test_suite array;
 */

// Batch 1
test_case_parameters batchTest_1[] = {
    // Check X
    {.pattern = "^(\\d+)-(\\d+)-(\\d+) (\\d+):(\\d+):(\\d\\d)$",
     .log = "2018-01-01 00:00:00",
     //.end_match = "0",
     .end_match = NULL,
     .captured_groups = (const char *[]){"2018", "01", "01", "00", "00", "00", NULL}},
    // Check X
    {.pattern = "^hi (\\w\\w\\w\\w\\w)",
     .log = "hi wazuh",
     .end_match = "h",
     .captured_groups = (const char *[]){"wazuh", NULL}},
    // Check X
    {.pattern = "^(\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+)",
     .log = "f1 f2 f3 f4 f5 f6 f7 f8 f9 f10",
     //.end_match = "0",
     .end_match = NULL,
     .captured_groups = (const char *[]){"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", NULL}},
    // End of check
    {0}};
// Batch 2
test_case_parameters batchTest_2[] = {
    // Check X
    {.pattern = "^hi (\\w+).",
     .log = "hi wazuh.bye",
     .end_match = ".bye",
     .captured_groups = (const char *[]){"wazuh", NULL}},
    // End of check
    {0}};

test_case_parameters * test_suite[] = {batchTest_1, batchTest_2, NULL};

void test_regex_execute_regex_matching(void ** state) {
    (void) state;
    unsigned char test = 0;

    regex_matching regex_match = {0};

    for (int batch_id = 0; test_suite[batch_id] != NULL; batch_id++) {
        memset(&regex_match, 0, sizeof(regex_matching));
        // Execute a batch of test cases
        for (int case_id = 0; test_suite[batch_id][case_id].pattern != NULL; case_id++) {
            exec_test_case(&test_suite[batch_id][case_id], &regex_match);
        }
        OSRegex_free_regex_matching(&regex_match);
    }

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_regex_execute_regex_matching),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

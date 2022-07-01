
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
    assert_non_null(match_retval); // The regex should match

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

// Tests

void test_regex_execute_regex_matching(void ** state) {
    (void) state;
    unsigned char test = 0;

    regex_matching regex_match = {0};
    memset(&regex_match, 0, sizeof(regex_matching));

    // Create a test case
    test_case_parameters t1 = {.pattern = "^hi (\\w\\w\\w\\w\\w)",
                               .log = "hi wazuh",
                               .end_match = "h",
                               .captured_groups = (const char *[]){"wazuh", NULL}};

    test_case_parameters t2 = {.pattern = "^(\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+) (\\w+)",
                               .log = "f1 f2 f3 f4 f5 f6 f7 f8 f9 f10",
                               //.end_match = "0", 
                               .end_match = NULL,
                               .captured_groups =
                                   (const char *[]){"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", NULL}};

    // Exectute a test case (A group of test cases can be shared the same regex_matching)
    exec_test_case(&t1, &regex_match);
    exec_test_case(&t2, &regex_match);


    OSRegex_free_regex_matching(&regex_match);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_regex_execute_regex_matching),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

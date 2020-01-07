/**
 * Test corresponding to the scheduling capacities
 * for command Module 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_command.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule command_module;
static unsigned test_command_date_counter = 0;
static struct tm test_command_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_command_date_storage[test_command_date_counter++] = *date;
    if(test_command_date_counter >= TEST_MAX_DATES){
        const wm_command_t *ptr = (wm_command_t *) command_module.data;
        check_function_ptr( &ptr->scan_config, &test_command_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    return 0;
}
/****************************************************************/

/******* Helpers **********/

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    wm_max_eps = 1;
    test_command_date_counter = 0;
    check_function_ptr = ptr;
}

static void run_test_string(const char *string){
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_command_read(nodes, &command_module, 0),0);
    command_module.context->start( (wm_command_t *) command_module.data);
}

/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<interval>1d</interval>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>";
    run_test_string(string);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<day>11</day>\n"
        "<time>12:30</time>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>";
    run_test_string(string);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<wday>Monday</wday>\n"
        "<time>10:00</time>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>";
    run_test_string(string);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<time>19:55</time>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>";
    run_test_string(string);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interval_execution),
        cmocka_unit_test(test_day_of_month),
        cmocka_unit_test(test_day_of_week),
        cmocka_unit_test(test_time_of_day),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

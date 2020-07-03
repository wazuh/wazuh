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

static wmodule *command_module;
static OS_XML *lxml;

static unsigned test_command_date_counter = 0;
static struct tm test_command_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this function to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_command_date_storage[test_command_date_counter++] = *date;
    *exitcode = 0;
    return 0;
}
/****************************************************************/
static void wmodule_cleanup(wmodule *module){
    wm_command_t* module_data = (wm_command_t *)module->data;
    free(module_data->sha256_hash);
    free(module_data->sha1_hash);
    free(module_data->full_command);
    free(module_data->command);
    free(module_data->tag);
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    command_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<interval>1d</interval>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    
    int ret = wm_command_read(nodes, command_module, 0);
    OS_ClearNode(nodes);
    return ret;
}

static int teardown_module(){
    wmodule_cleanup(command_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state){
    wm_max_eps = 1;
    test_command_date_counter = 0;
    return 0;
}

static int teardown_test_executions(void **state){
    wm_command_t* module_data = (wm_command_t *) *state;
    sched_scan_free(&(module_data->scan_config));
    return 0;
}

static int setup_test_read(void **state) {
    test_structure *test = calloc(1, sizeof(test_structure));
    test->module =  calloc(1, sizeof(wmodule));
    *state = test;   
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/** Tests **/
void test_interval_execution(void **state) {
    wm_command_t* module_data = (wm_command_t *)command_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    command_module->context->start(module_data);
    check_time_interval( &module_data->scan_config, &test_command_date_storage[0], TEST_MAX_DATES);     
}

void test_day_of_month(void **state) {
    wm_command_t* module_data = (wm_command_t *)command_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 13;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    command_module->context->start(module_data);
    check_day_of_month( &module_data->scan_config, &test_command_date_storage[0], TEST_MAX_DATES);
}

void test_day_of_week(void **state) {
    wm_command_t* module_data = (wm_command_t *)command_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    command_module->context->start(module_data);
    check_day_of_week( &module_data->scan_config, &test_command_date_storage[0], TEST_MAX_DATES);
}

void test_time_of_day(void **state) {
    wm_command_t* module_data = (wm_command_t *)command_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("05:25");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    command_module->context->start(module_data);
    check_time_of_day( &module_data->scan_config, &test_command_date_storage[0], TEST_MAX_DATES);
}

void test_fake_tag(void **state) {
    const char *string =
        "<fake>True</fake>\n"
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
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>12:05</time>\n"
        "<day>1</day>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 1);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "12:05");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>10:59</time>\n"
        "<wday>Tuesday</wday>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 2);
    assert_string_equal(module_data->scan_config.scan_time, "10:59");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>10:53</time>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "10:53");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<interval>10s</interval>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 10); // 10 seconds
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_day_of_month, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_day_of_week, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_time_of_day, setup_test_executions, teardown_test_executions)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_monthday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_weekday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_daytime_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_interval_configuration, setup_test_read, teardown_test_read)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}

/**
 * Test corresponding to the scheduling capacities
 * for aws Module 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_aws.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *aws_module;
static OS_XML *lxml;

static unsigned test_aws_date_counter = 0;
static struct tm test_aws_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_aws_date_storage[test_aws_date_counter++] = *date;
    if(test_aws_date_counter >= TEST_MAX_DATES){
        const wm_aws *ptr = (wm_aws *) aws_module->data;
        check_function_ptr( &ptr->scan_config, &test_aws_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
        int i;
    }
    *exitcode = 0;
    return 0;
}
/****************************************************************/

/******* Helpers **********/
static void set_config_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    wm_max_eps = 1;
    test_aws_date_counter = 0;
    check_function_ptr = ptr;
}
/****************************************************************/

static void wmodule_cleanup(wmodule *module){
    free( ((wm_aws*) module->data)->buckets->bucket);
    free( ((wm_aws*) module->data)->buckets->aws_profile);
    free( ((wm_aws*) module->data)->buckets->trail_prefix);
    free( ((wm_aws*) module->data)->buckets->type);
    free( ((wm_aws*) module->data)->buckets);
    free(module->data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    aws_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>10m</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    assert_int_equal(wm_aws_read(lxml, nodes, aws_module), 0);
    OS_ClearNode(nodes);
    return 0;
}

static int teardown_module(){
    wmodule_cleanup(aws_module);
    OS_ClearXML(lxml);
    return 0;
}

/** Tests **/
void test_interval_execution() {
    set_config_test(check_time_interval);
    wm_aws* module_data = (wm_aws *)aws_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 600; // 10min
    module_data->scan_config.month_interval = false;
    aws_module->context->start(module_data);
}

void test_day_of_month() {
    set_config_test(check_day_of_month);
    wm_aws* module_data = (wm_aws *)aws_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 3;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time =strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    aws_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_day_of_week() {
    set_config_test(check_day_of_week);
    wm_aws* module_data = (wm_aws *)aws_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 6;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    aws_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_time_of_day() {
    set_config_test(check_time_of_day);
    wm_aws* module_data = (wm_aws *)aws_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    aws_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}


void test_fake_tag() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
        "<fake-tag>ASD</fake-tag>"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_aws_read(&xml, nodes, module), -1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wm_aws *module_data = (wm_aws*)module->data;
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
    
}

void test_read_scheduling_monthday_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<day>6</day>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_aws_read(&xml, nodes, module), 0);
    wm_aws *module_data = (wm_aws*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 6);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "15:05");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_weekday_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>13:03</time>\n"
        "<wday>Monday</wday>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_aws_read(&xml, nodes, module), 0);
    wm_aws *module_data = (wm_aws*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 1);
    assert_string_equal(module_data->scan_config.scan_time, "13:03");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_daytime_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>01:11</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_aws_read(&xml, nodes, module), 0);
    wm_aws *module_data = (wm_aws*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "01:11");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_interval_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>10m</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_aws_read(&xml, nodes, module), 0);
    wm_aws *module_data = (wm_aws*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 600);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wmodule_cleanup(module);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test(test_interval_execution),
        cmocka_unit_test(test_day_of_month),
        cmocka_unit_test(test_day_of_week),
        cmocka_unit_test(test_time_of_day)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test(test_fake_tag),
        cmocka_unit_test(test_read_scheduling_monthday_configuration),
        cmocka_unit_test(test_read_scheduling_weekday_configuration),
        cmocka_unit_test(test_read_scheduling_daytime_configuration),
        cmocka_unit_test(test_read_scheduling_interval_configuration)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result &= cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}

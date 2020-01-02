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

static wmodule aws_module;
static unsigned test_aws_date_counter = 0;
static struct tm test_aws_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_aws_date_storage[test_aws_date_counter++] = *date;
    if(test_aws_date_counter >= TEST_MAX_DATES){
        const wm_aws *ptr = (wm_aws *) aws_module.data;
        check_function_ptr( &ptr->scan_config, &test_aws_date_storage[0], TEST_MAX_DATES);
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
    test_aws_date_counter = 0;
    check_function_ptr = ptr;
}


/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>10m</interval>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
}

void test_day_of_month(){
    set_up_test(check_day_of_month);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<day>3</day>\n"
        "<time>0:00</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
}

void test_day_of_week(){
    set_up_test(check_day_of_week);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<wday>Sunday</wday>\n"
        "<time>0:00</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
}

void test_time_of_day(){
    set_up_test(check_time_of_day);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
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
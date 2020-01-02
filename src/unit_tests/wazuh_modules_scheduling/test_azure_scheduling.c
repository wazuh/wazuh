/**
 * Test corresponding to the scheduling capacities
 * for aws Module
 * 
 * To add this tests on CMAKE:
 *  
 * 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_azure.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule azure_module;
static unsigned test_azure_date_counter = 0;
static struct tm test_azure_date_storage[TEST_MAX_DATES];
/**
 *  Since module run is in a loop we pass a function ptr 
 * to use when cut condition is met in wrapped funcion
 * */
static void (*check_function_ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES) = 0;

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_azure_date_storage[test_azure_date_counter++] = *date;
    if(test_azure_date_counter >= TEST_MAX_DATES){
        const wm_azure_t *ptr = (wm_azure_t *) azure_module.data;
        check_function_ptr( &ptr->scan_config, &test_azure_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    return 0;
}


static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    if((wm_azure_t *) azure_module.data){
        // Free data to generate a new initialziation between tests
        os_free(azure_module.data);
        azure_module.data = NULL;
    }
    enable_forever_loop();
    test_azure_date_counter = 0;
    check_function_ptr = ptr;
}

static void run_test_string(const char *string){
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_azure_read(&lxml, nodes, &azure_module),0);
    azure_module.context->start( (wm_azure_t *) azure_module.data);
}

void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>5m</interval>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<log_analytics>\n"
        "    <application_id>8b7...c14</application_id>\n"
        "    <application_key>w22...91x</application_key>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    run_test_string(string);
}

void test_day_of_month(){
    set_up_test(check_day_of_month);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<day>21</day>\n"
        "<time>0:00</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <application_id>8b7...c14</application_id>\n"
        "    <application_key>w22...91x</application_key>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    run_test_string(string);
}

void test_day_of_week(){
    set_up_test(check_day_of_week);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<wday>Wednesday</wday>\n"
        "<time>23:59</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <application_id>8b7...c14</application_id>\n"
        "    <application_key>w22...91x</application_key>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    run_test_string(string);
}

void test_time_of_day(){
    set_up_test(check_time_of_day);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>00:01</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <application_id>8b7...c14</application_id>\n"
        "    <application_key>w22...91x</application_key>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
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
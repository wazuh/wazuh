/**
 * Test corresponding to the scheduling capacities
 * for azure Module
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

static wmodule *azure_module;
static OS_XML *lxml;

static unsigned test_azure_date_counter = 0;
static struct tm test_azure_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this function to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_azure_date_storage[test_azure_date_counter++] = *date;
    *exitcode = 0;
    return 0;
}

int __wrap_SendMSG(int queue, const char *message, const char *locmsg, char loc) {
    return 0;
}

static void wmodule_cleanup(wmodule *module){
    wm_azure_t* module_data = (wm_azure_t *)module->data;
    if(module_data->api_config){
        free(module_data->api_config->application_key);
        free(module_data->api_config->application_id);
        free(module_data->api_config->tenantdomain);
        free(module_data->api_config->request->time_offset);
        free(module_data->api_config->request->workspace);
        free(module_data->api_config->request->query);
        free(module_data->api_config->request->tag);
        free(module_data->api_config->request);
        free(module_data->api_config);
    }
    free(module_data);
    free(module->tag);
    free(module);
}


/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    azure_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>5m</interval>\n"
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
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_azure_read(lxml, nodes, azure_module);
    OS_ClearNode(nodes);
    return ret;
}

static int teardown_module(){
    wmodule_cleanup(azure_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    test_azure_date_counter = 0;
    return 0;
}

static int teardown_test_executions(void **state){
    wm_azure_t* module_data = (wm_azure_t *) *state;
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
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}
/************************************/

void test_interval_execution(void **state) {
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 1200; // 20min
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    azure_module->context->start(module_data);
    check_time_interval( &module_data->scan_config, &test_azure_date_storage[0], TEST_MAX_DATES);
}

void test_day_of_month(void **state) {
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 20;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    azure_module->context->start(module_data);
    check_day_of_month( &module_data->scan_config, &test_azure_date_storage[0], TEST_MAX_DATES);
}

void test_day_of_week(void **state) {
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    azure_module->context->start(module_data);
    check_day_of_week( &module_data->scan_config, &test_azure_date_storage[0], TEST_MAX_DATES);
}

void test_time_of_day(void **state) {
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    azure_module->context->start(module_data);
    check_time_of_day( &module_data->scan_config, &test_azure_date_storage[0], TEST_MAX_DATES);
}

void test_fake_tag(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<fake_tag>1</fake_tag>\n"
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
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>00:01</time>\n"
        "<day>4</day>\n"
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
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 4);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "00:01");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>00:01</time>\n"
        "<wday>Friday</wday>\n"
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
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 5);
    assert_string_equal(module_data->scan_config.scan_time, "00:01");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>00:10</time>\n"
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
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "00:10");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>3h</interval>\n"
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
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 3600*3);
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

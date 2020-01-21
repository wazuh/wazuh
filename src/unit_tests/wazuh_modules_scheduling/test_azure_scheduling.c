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
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_azure_date_storage[test_azure_date_counter++] = *date;
    if(test_azure_date_counter >= TEST_MAX_DATES){
        const wm_azure_t *ptr = (wm_azure_t *) azure_module->data;
        check_function_ptr( &ptr->scan_config, &test_azure_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    *exitcode = 0;
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
    assert_int_equal(wm_azure_read(lxml, nodes, azure_module), 0);
    OS_ClearNode(nodes);
    return 0;
}

static int teardown_module(){
    wmodule_cleanup(azure_module);
    OS_ClearXML(lxml);
    return 0;
}
/************************************/

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    test_azure_date_counter = 0;
    check_function_ptr = ptr;
}

void test_interval_execution() {
    set_up_test(check_time_interval);
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 1200; // 20min
    module_data->scan_config.month_interval = false;
    azure_module->context->start(module_data);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 20;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    azure_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    azure_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    azure_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_fake_tag() {
    set_up_test(check_time_of_day);
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
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_azure_read(&xml, nodes, module),-1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wm_azure_t *module_data = (wm_azure_t*)module->data;
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_monthday_configuration() {
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
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_azure_read(&xml, nodes, module), 0);
    wm_azure_t *module_data = (wm_azure_t*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 4);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "00:01");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_weekday_configuration() {
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
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_azure_read(&xml, nodes, module), 0);
    wm_azure_t *module_data = (wm_azure_t*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 5);
    assert_string_equal(module_data->scan_config.scan_time, "00:01");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_daytime_configuration() {
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
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_azure_read(&xml, nodes, module), 0);
    wm_azure_t *module_data = (wm_azure_t*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "00:10");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_interval_configuration() {
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
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_azure_read(&xml, nodes, module), 0);
    wm_azure_t *module_data = (wm_azure_t*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 3600*3);
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

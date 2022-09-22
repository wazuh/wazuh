/**
 * Test corresponding to the scheduling capacities
 * for gcp Module
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_gcp.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *gcp_module;
static OS_XML *lxml;

static unsigned test_gcp_date_counter = 0;
static struct tm test_gcp_date_storage[TEST_MAX_DATES];

extern void wm_gcp_run(const wm_gcp *data);

char *__wrap_realpath(const char *path, char *resolved_path) {
    return (char *)mock();
}

int __wrap_IsFile(const char* path){
    return mock();
}

void wm_gcp_run(const wm_gcp *data) {
    // Will wrap this function to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_gcp_date_storage[test_gcp_date_counter++] = *date;
}

static void wmodule_cleanup(wmodule *module){
    wm_gcp* module_data = (wm_gcp *)module->data;
    free(module_data->project_id);
    free(module_data->credentials_file);
    free(module_data->subscription_name);
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    gcp_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<interval>2m</interval>\n"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    will_return(__wrap_realpath, "TEST_STRING");
    will_return(__wrap_IsFile, 0); 
    int ret = wm_gcp_read(nodes, gcp_module);
    OS_ClearNode(nodes);
    return ret;
}

static int teardown_module(){
    wmodule_cleanup(gcp_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    test_gcp_date_counter = 0;
    return 0;
}


static int teardown_test_executions(void **state){
    wm_gcp* module_data = (wm_gcp *) *state;
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
    wm_gcp *module_data = (wm_gcp*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/** Tests **/
void test_interval_execution(void **state) {
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    gcp_module->context->start(module_data);
    check_time_interval( &module_data->scan_config, &test_gcp_date_storage[0], TEST_MAX_DATES);   
}

void test_day_of_month(void **state){
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 13;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    gcp_module->context->start(module_data);
    check_day_of_month( &module_data->scan_config, &test_gcp_date_storage[0], TEST_MAX_DATES);  
}

void test_day_of_week(void **state){
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    gcp_module->context->start(module_data);
    check_day_of_week( &module_data->scan_config, &test_gcp_date_storage[0], TEST_MAX_DATES);    
}

void test_time_of_day(void **state){
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("05:25");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    gcp_module->context->start(module_data);
    check_time_of_day( &module_data->scan_config, &test_gcp_date_storage[0], TEST_MAX_DATES);
}


void test_fake_tag(void **state){
    const char *string = 
       "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<time>18:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<tag>yes</tag>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    will_return(__wrap_realpath, "TEST_STRING");
    will_return(__wrap_IsFile, 0);
    assert_int_equal(wm_gcp_read(test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<day>6</day>\n"
        "<time>11:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    will_return(__wrap_realpath, "TEST_STRING");
    will_return(__wrap_IsFile, 0);
    assert_int_equal(wm_gcp_read(test->nodes, test->module),0);
    wm_gcp *module_data = (wm_gcp*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 6);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "11:00");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<wday>Sunday</wday>\n"
        "<time>23:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    will_return(__wrap_realpath, "TEST_STRING");
    will_return(__wrap_IsFile, 0);
    assert_int_equal(wm_gcp_read(test->nodes, test->module),0);
    wm_gcp *module_data = (wm_gcp*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 0);
    assert_string_equal(module_data->scan_config.scan_time, "23:00");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<time>21:43</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    will_return(__wrap_realpath, "TEST_STRING");
    will_return(__wrap_IsFile, 0);
    assert_int_equal(wm_gcp_read(test->nodes, test->module),0);
    wm_gcp *module_data = (wm_gcp*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "21:43");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<interval>24h</interval>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    will_return(__wrap_realpath, "TEST_STRING");
    will_return(__wrap_IsFile, 0);
    assert_int_equal(wm_gcp_read(test->nodes, test->module),0);
    wm_gcp *module_data = (wm_gcp*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
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

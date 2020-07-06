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
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/schedule_scan_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *gcp_module;
static OS_XML *lxml;
extern int test_mode;

extern void wm_gcp_run(const wm_gcp *data);

int __wrap_IsFile(const char* path){
    return mock();
}

void wm_gcp_run(const wm_gcp *data) {
    // Will wrap this function to check running times in order to check scheduling
    return;
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

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);

    will_return(__wrap_IsFile, 0);
    int ret = wm_gcp_read(nodes, gcp_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(gcp_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
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

    expect_value_count(__wrap_sched_scan_get_time_until_next_scan, config, &module_data->scan_config, TEST_MAX_DATES + 1);
    expect_string_count(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_GCP_LOGTAG, TEST_MAX_DATES + 1);
    expect_value_count(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 0, TEST_MAX_DATES + 1);
    will_return_count(__wrap_sched_scan_get_time_until_next_scan, 0, TEST_MAX_DATES);
    will_return(__wrap_sched_scan_get_time_until_next_scan, 1);
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    gcp_module->context->start(module_data);
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

    expect_string(__wrap__merror, formatted_msg, "No such tag 'tag' at module 'gcp-pubsub'.");
    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);

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
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);

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
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);

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
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    test->nodes = string_to_xml_node(string, &(test->xml));

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);

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

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);

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
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions)
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

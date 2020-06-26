/**
 * Test corresponding to the scheduling capacities
 * for SCA Module 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include <stdlib.h>
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 3

static wmodule *sca_module;
static OS_XML *lxml;

static unsigned test_sca_date_counter = 0;
static struct tm test_sca_date_storage[TEST_MAX_DATES];

extern void wm_sca_send_policies_scanned(wm_sca_t * data);

extern w_queue_t * request_queue;
extern char **last_sha256;
extern OSHash **cis_db;
extern struct cis_db_hash_info_t *cis_db_for_hash;
extern unsigned int policies_count;

int __wrap_IsFile(const char *file)
{
    return 0;
}

int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max)
{
    if( !strcmp(low_name, "request_db_interval") ) {
        return 5;
    }
    if( !strcmp(low_name, "commands_timeout") ) {
        return 300;
    }
    return 0;
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    return 1;
}

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    return 0;
}

int __wrap_wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {
    return 0;
}

void wm_sca_send_policies_scanned(wm_sca_t * data)
{
    // Will wrap this function to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_sca_date_storage[test_sca_date_counter++] = *date;
}

/******* Helpers **********/

static void wmodule_cleanup(wmodule *module){
    wm_sca_t* module_data = (wm_sca_t *)module->data;
    int i;
    for(i = 0; i < policies_count; i++) {
        os_free(module_data->policies[i]->policy_path);
        os_free(module_data->policies[i]);
    }
    os_free(module_data->alert_msg);
    os_free(module_data->policies);
    os_free(module_data);
    os_free(module->tag);
    os_free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    sca_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<interval>12h</interval>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_sca_read(lxml, nodes, sca_module);
    OS_ClearNode(nodes);
    return ret;
}

static int teardown_module(){
    wm_sca_t* module_data = (wm_sca_t *)sca_module->data;
    wmodule_cleanup(sca_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    test_sca_date_counter = 0;
    return 0;
}

static int teardown_test_executions(void **state) {
    wm_sca_t* module_data = (wm_sca_t *)sca_module->data;
    sched_scan_free(&(module_data->scan_config));
    int i;
    for(i = 0; module_data->policies[i]; i++) {
        os_free(last_sha256[i]);
        OSHash_Free(cis_db[i]);
        os_free(cis_db_for_hash[i].elem);
    }
    queue_free(request_queue);
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
    wmodule *module = test->module;
    wm_sca_t* module_data = (wm_sca_t *)module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(module);
    os_free(test);
    return 0;
}

/****************************************************************/


/** Tests **/
void test_interval_execution(void **state) {
    wm_sca_t* module_data = (wm_sca_t *)sca_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    sca_module->context->start(module_data);
    check_time_interval( &module_data->scan_config, &test_sca_date_storage[0], TEST_MAX_DATES);   
}

void test_day_of_month(void **state) {
    wm_sca_t* module_data = (wm_sca_t *)sca_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 13;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    sca_module->context->start(module_data);
    check_day_of_month( &module_data->scan_config, &test_sca_date_storage[0], TEST_MAX_DATES);   
}

void test_day_of_week(void **state) {
    wm_sca_t* module_data = (wm_sca_t *)sca_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    sca_module->context->start(module_data);
    check_day_of_week( &module_data->scan_config, &test_sca_date_storage[0], TEST_MAX_DATES);
}

void test_time_of_day(void **state) {
    wm_sca_t* module_data = (wm_sca_t *)sca_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("05:25");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    sca_module->context->start(module_data);
    check_time_of_day( &module_data->scan_config, &test_sca_date_storage[0], TEST_MAX_DATES);
}

void test_fake_tag(void **state) {
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<time>03:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n"
        "<fake>invalid</fake>";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_sca_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<day>7</day>\n"
        "<time>03:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_sca_read(&(test->xml), test->nodes, test->module),0);
    wm_sca_t* module_data = (wm_sca_t *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 7);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "03:30");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<wday>Monday</wday>\n"
        "<time>04:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_sca_read(&(test->xml), test->nodes, test->module),0);
    wm_sca_t* module_data = (wm_sca_t *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 1);
    assert_string_equal(module_data->scan_config.scan_time, "04:30");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<time>05:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_sca_read(&(test->xml), test->nodes, test->module),0);
    wm_sca_t* module_data = (wm_sca_t *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "05:30");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<interval>2h</interval>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_sca_read(&(test->xml), test->nodes, test->module),0);
    wm_sca_t* module_data = (wm_sca_t *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 7200);
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

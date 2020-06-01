/**
 * Test corresponding to the scheduling capacities
 * for oscap Module 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_oscap.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *oscap_module;
static OS_XML *lxml;

static unsigned test_oscap_date_counter = 0;
static struct tm test_oscap_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this function to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_oscap_date_storage[test_oscap_date_counter++] = *date;
    *exitcode = 0;
    *output = strdup("TEST_STRING");
    return 0;
}

int __wrap_wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {
    return 0;
}

int __wrap_SendMSG(int queue, const char *message, const char *locmsg, char loc) {
    return 0;
}


/******* Helpers **********/

static void wmodule_cleanup(wmodule *module){
    wm_oscap* module_data = (wm_oscap *)module->data;
    if (module_data->evals) {
        wm_oscap_eval* eval = module_data->evals;
        while(eval->next){
            wm_oscap_eval* aux= eval;
            eval = eval->next;
            free(aux->path);
            free(aux);
        }
        free(module_data->evals->path);
        free(module_data->evals);
    }
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    oscap_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<interval>12h</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<content type=\"xccdf\" path=\"ssg-centos-6-ds.xml\"/>\n";
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_oscap_read(lxml, nodes, oscap_module);
    OS_ClearNode(nodes);
    return ret;
}

static int teardown_module(){
    wmodule_cleanup(oscap_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    test_oscap_date_counter = 0;
    return 0;
}

static int teardown_test_executions(void **state){
    wm_oscap* module_data = (wm_oscap *) *state;
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
    wm_oscap *module_data = (wm_oscap*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/****************************************************************/

/** Tests **/
void test_interval_execution(void **state) {
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    oscap_module->context->start(module_data);
    check_time_interval( &module_data->scan_config, &test_oscap_date_storage[0], TEST_MAX_DATES);
}

void test_day_of_month(void **state) {
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 13;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    oscap_module->context->start(module_data);
    check_day_of_month( &module_data->scan_config, &test_oscap_date_storage[0], TEST_MAX_DATES);
}

void test_day_of_week(void **state) {
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    oscap_module->context->start(module_data);
    check_day_of_week( &module_data->scan_config, &test_oscap_date_storage[0], TEST_MAX_DATES);
}

void test_time_of_day(void **state) {
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("05:25");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    oscap_module->context->start(module_data);
    check_time_of_day( &module_data->scan_config, &test_oscap_date_storage[0], TEST_MAX_DATES);
}

void test_fake_tag(void **state) {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<time>1:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<fake_tag>null<fake_tag/>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<day>8</day>\n"
        "<time>01:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 8);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "01:15");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<wday>Saturday</wday>\n"
        "<time>01:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 6);
    assert_string_equal(module_data->scan_config.scan_time, "01:15");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<time>21:43</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "21:43");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<interval>90m</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 90*60);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_day_of_month, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_day_of_week, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_time_of_day, setup_test_executions, teardown_test_executions),
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

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
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_oscap_date_storage[test_oscap_date_counter++] = *date;
    if(test_oscap_date_counter >= TEST_MAX_DATES){
        const wm_oscap *ptr = (wm_oscap *) oscap_module->data;
        check_function_ptr( &ptr->scan_config, &test_oscap_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    *exitcode = 0;
    *output = strdup("TEST_STRING");
    return 0;
}

int __wrap_wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {
    return 0;
}

/******* Helpers **********/

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    wm_max_eps = 1;
    test_oscap_date_counter = 0;
    check_function_ptr = ptr;
}

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
    assert_int_equal(wm_oscap_read(lxml, nodes, oscap_module), 0);
    OS_ClearNode(nodes);
    return 0;
}

static int teardown_module(){
    wmodule_cleanup(oscap_module);
    OS_ClearXML(lxml);
    return 0;
}

/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;
    oscap_module->context->start(module_data);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 13;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    oscap_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    oscap_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("05:25");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    oscap_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_fake_tag() {
    set_up_test(check_time_of_day);
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<time>1:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<fake_tag>null<fake_tag/>\n";
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_oscap_read(&xml, nodes, module),-1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wm_oscap* module_data = (wm_oscap *)module->data;
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_monthday_configuration() {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<day>8</day>\n"
        "<time>01:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_oscap_read(&xml, nodes, module),0);
    wm_oscap *module_data = (wm_oscap*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 8);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "01:15");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_weekday_configuration() {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<wday>Saturday</wday>\n"
        "<time>01:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_oscap_read(&xml, nodes, module),0);
    wm_oscap *module_data = (wm_oscap*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 6);
    assert_string_equal(module_data->scan_config.scan_time, "01:15");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_daytime_configuration() {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<time>21:43</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_oscap_read(&xml, nodes, module),0);
    wm_oscap *module_data = (wm_oscap*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "21:43");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_interval_configuration() {
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<interval>90m</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_oscap_read(&xml, nodes, module),0);
    wm_oscap *module_data = (wm_oscap*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 90*60);
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

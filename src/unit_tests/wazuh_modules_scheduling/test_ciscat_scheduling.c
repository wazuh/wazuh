/**
 * Test corresponding to the scheduling capacities
 * for ciscat Module 
 * */
#define ENABLE_CISCAT
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_ciscat.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *ciscat_module;
static OS_XML *lxml;

static unsigned test_ciscat_date_counter = 0;
static struct tm test_ciscat_date_storage[TEST_MAX_DATES];

int __wrap_os_random() {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_ciscat_date_storage[test_ciscat_date_counter++] = *date;
    if(test_ciscat_date_counter >= TEST_MAX_DATES){
        const wm_ciscat *ptr = (wm_ciscat *) ciscat_module->data;
        check_function_ptr( &ptr->scan_config, &test_ciscat_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    return 0;
}

int __wrap_IsDir(const char *file) {
    // Bypass dir verification in main loop
    return 0;
}

static void wmodule_cleanup(wmodule *module){
    wm_ciscat* module_data = (wm_ciscat *) module->data;
    wm_ciscat_eval *eval = module_data->evals;
    while(eval != 0) {
        wm_ciscat_eval *aux = eval;
        eval = eval->next;
        free(aux->profile);
        free(aux->path);
        free(aux);
    }
    free(module_data->ciscat_path);
    free(module_data->java_path);
    free(module_data);
    free(module->tag);
    free(module);
}

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    test_ciscat_date_counter = 0;
    check_function_ptr = ptr;
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    ciscat_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>3m</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    assert_int_equal(wm_ciscat_read(lxml, nodes, ciscat_module), 0);
    OS_ClearNode(nodes);
    return 0;
}

static int teardown_module(){
    wmodule_cleanup(ciscat_module);
    OS_ClearXML(lxml);
    return 0;
}
/************************************/

void test_interval_execution() {
    set_up_test(check_time_interval);
    wm_ciscat* module_data = (wm_ciscat *)ciscat_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 120; // 2min
    module_data->scan_config.month_interval = false;
    ciscat_module->context->start(module_data);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    wm_ciscat* module_data = (wm_ciscat *)ciscat_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 15;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    ciscat_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    wm_ciscat* module_data = (wm_ciscat *)ciscat_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    ciscat_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    wm_ciscat* module_data = (wm_ciscat *)ciscat_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    ciscat_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_fake_tag() {
    set_up_test(check_time_of_day);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<invalid-tag>laklsdaklsa</invalid-tag>"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
    ;
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_ciscat_read(&xml, nodes, module),-1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wm_ciscat* module_data = (wm_ciscat *)module->data;
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_monthday_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<day>5</day>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_ciscat_read(&xml, nodes, module), 0);
    wm_ciscat* module_data = (wm_ciscat *)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 5);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "14:59");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_weekday_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>23:59</time>\n"
        "<wday>Wednesday</wday>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_ciscat_read(&xml, nodes, module), 0);
    wm_ciscat* module_data = (wm_ciscat *)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 3);
    assert_string_equal(module_data->scan_config.scan_time, "23:59");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_daytime_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>11:45</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_ciscat_read(&xml, nodes, module), 0);
    wm_aws *module_data = (wm_aws*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "11:45");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_interval_configuration() {
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>1h</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_ciscat_read(&xml, nodes, module), 0);
    wm_aws *module_data = (wm_aws*)module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 3600);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
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

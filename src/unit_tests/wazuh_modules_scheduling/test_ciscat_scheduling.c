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

static wmodule ciscat_module;
static unsigned test_ciscat_date_counter = 0;
static struct tm test_ciscat_date_storage[TEST_MAX_DATES];

int __wrap_os_random() {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_ciscat_date_storage[test_ciscat_date_counter++] = *date;
    if(test_ciscat_date_counter >= TEST_MAX_DATES){
        const wm_ciscat *ptr = (wm_ciscat *) ciscat_module.data;
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

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    if( (struct wm_ciscat *) ciscat_module.data){
        // Free data to generate a new initialziation between tests
        os_free(ciscat_module.data);
        ciscat_module.data = NULL;
    }
    enable_forever_loop();
    test_ciscat_date_counter = 0;
    check_function_ptr = ptr;
}

static void run_test_string(const char *string) {
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_ciscat_read(&lxml, nodes, &ciscat_module),0);
    ciscat_module.context->start( (struct wm_ciscat *) ciscat_module.data);
}

void test_interval_execution() {
    set_up_test(check_time_interval);
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
    run_test_string(string);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<day>20</day>\n"
        "<time>2:30</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    run_test_string(string);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<wday>Thursday</wday>\n"
        "<time>11:59</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
    ;
    run_test_string(string);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n" 
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
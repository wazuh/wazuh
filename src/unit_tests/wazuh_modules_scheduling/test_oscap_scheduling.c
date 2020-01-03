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

static wmodule oscap_module;
static unsigned test_oscap_date_counter = 0;
static struct tm test_oscap_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_oscap_date_storage[test_oscap_date_counter++] = *date;
    if(test_oscap_date_counter >= TEST_MAX_DATES){
        const wm_oscap *ptr = (wm_oscap *) oscap_module.data;
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

static void run_test_string(const char *string){
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_oscap_read(&lxml, nodes, &oscap_module),0);
    oscap_module.context->start( (wm_docker_t *) oscap_module.data);
}

/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<interval>12h</interval>\n"
        "<scan-on-start>yes</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<content type=\"xccdf\" path=\"ssg-centos-6-ds.xml\"/>\n";
    run_test_string(string);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<day>5</day>\n"
        "<time>12:30</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<content type=\"xccdf\" path=\"ssg-centos-6-ds.xml\"/>\n";
    run_test_string(string);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<wday>Wednesday</wday>\n"
        "<time>2:30</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<content type=\"xccdf\" path=\"ssg-centos-6-ds.xml\"/>\n";
    run_test_string(string);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    const char *string = 
        "<timeout>1800</timeout>\n"
        "<time>1:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<content type=\"xccdf\" path=\"ssg-centos-6-ds.xml\"/>\n";
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
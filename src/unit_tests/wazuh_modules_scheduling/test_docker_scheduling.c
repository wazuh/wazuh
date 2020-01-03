/**
 * Test corresponding to the scheduling capacities
 * for docker Module 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_docker.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule docker_module;
static unsigned test_docker_date_counter = 0;
static struct tm test_docker_date_storage[TEST_MAX_DATES];

int __wrap_wpclose(wfd_t * wfd) {
    __real_wpclose(wfd);
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_docker_date_storage[test_docker_date_counter++] = *date;
    if(test_docker_date_counter >= TEST_MAX_DATES){
        const wm_docker_t *ptr = (wm_docker_t *) docker_module.data;
        check_function_ptr( &ptr->scan_config, &test_docker_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    return 0;
}

/******* Helpers **********/

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    wm_max_eps = 1;
    test_docker_date_counter = 0;
    check_function_ptr = ptr;
}

static void run_test_string(const char *string){
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_docker_read(nodes, &docker_module),0);
    docker_module.context->start( (wm_docker_t *) docker_module.data);
}

/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n";
    run_test_string(string);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    const char *string = 
        "<day>11</day>\n"
        "<time>12:30</time>\n"
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n";
    run_test_string(string);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    const char *string =
        "<wday>Monday</wday>\n"
        "<time>10:00</time>\n"
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n";
    run_test_string(string);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    const char *string =
        "<time>19:55</time>\n"
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n";
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
/**
 * Test corresponding to the scheduling capacities
 * for SCA Module 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 3

static wmodule sca_module;
static unsigned test_sca_date_counter = 0;
static struct tm test_sca_date_storage[TEST_MAX_DATES];

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

void __wrap__mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    if( !strcmp(msg, "Starting Security Configuration Assessment scan.") ) {
        // Will wrap this funciont to check running times in order to check scheduling
        time_t current_time = time(NULL);
        struct tm *date = localtime(&current_time);
        test_sca_date_storage[test_sca_date_counter++] = *date;
        if(test_sca_date_counter >= TEST_MAX_DATES){
            const wm_sca_t *ptr = (wm_sca_t *) sca_module.data;
            check_function_ptr( &ptr->scan_config, &test_sca_date_storage[0], TEST_MAX_DATES);
            // Break infinite loop
            disable_forever_loop();
        }
    }
}

/******* Helpers **********/

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    if((wm_sca_t *) sca_module.data){
        // Free data to generate a new initialziation between tests
        os_free(sca_module.data);
        sca_module.data = NULL;
    }
    enable_forever_loop();
    wm_max_eps = 1;
    test_sca_date_counter = 0;
    check_function_ptr = ptr;
}

static void run_test_string(const char *string){
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_sca_read(&lxml, nodes, &sca_module),0);
    sca_module.context->start( (wm_sca_t *) sca_module.data);
}

/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<interval>12h</interval>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    run_test_string(string);
}

void test_day_of_month() {
    set_up_test(check_day_of_month);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<day>1</day>\n"
        "<time>9:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    run_test_string(string);
}

void test_day_of_week() {
    set_up_test(check_day_of_week);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<wday>Friday</wday>\n"
        "<time>6:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
    run_test_string(string);
}

void test_time_of_day() {
    set_up_test(check_time_of_day);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<time>3:30</time>\n"
        "<policies>\n"
        "    <policy>/var/ossec/etc/shared/your_policy_file.yml</policy>\n"
        "</policies>\n";
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
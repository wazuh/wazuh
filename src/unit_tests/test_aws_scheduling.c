/**
 * Test corresponding to the scheduling capacities
 * for aws Module
 * 
 * To add this tests on CMAKE:
 *  
 *  list(APPEND tests_names "test_aws_scheduling")
 *  list(APPEND tests_flags "-Wl,--wrap=time,--wrap=wm_delay,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_exec,--wrap=StartMQ,--wrap=FOREVER")
 * 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_aws.h"

#define MAX_DATES 5

static wmodule aws_module;
static unsigned test_aws_date_counter = 0;
static struct tm test_aws_date_storage[MAX_DATES];
/**
 *  Since module run is in a loop we pass a function ptr 
 * to use when cut condition is met in wrapped funcion
 * */
static void (*check_function_ptr)() = 0;

/**     Mocked functions       **/
static time_t current_time = 0; 
static int FOREVER_LOOP = 1;

time_t __wrap_time(time_t *_time){
    if(!current_time){
        current_time = __real_time(NULL);
    }
    return current_time;
}

void __wrap_wm_delay(unsigned int msec){
    current_time += (msec/1000);
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...){
    return;
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...){
    return;
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mtwarn(const char *tag, const char * file, int line, const char * func, const char *msg, ...){
    return;
}

//Function that defines the ending of the module main loop
int __wrap_FOREVER(){
    return FOREVER_LOOP;
}

int __wrap_StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type)
{
    return (0);
}

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_aws_date_storage[test_aws_date_counter++] = *date;
    if(test_aws_date_counter >= MAX_DATES){
        check_function_ptr();
        // Break infinite loop
        FOREVER_LOOP = 0;
    }
    return 0;
}
/****************************************************************/

/******* Helpers **********/
static const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml){
    XML_NODE nodes;
    OS_ReadXMLString(string, _lxml);
    nodes = OS_GetElementsbyNode(_lxml, NULL);
    return nodes;
}

static void set_up_test(void (*ptr)()) {
    FOREVER_LOOP = 1;
    wm_max_eps = 1;
    test_aws_date_counter = 0;
    check_function_ptr = ptr;
}

/**
 * Test interval between consecutive runs matches configuration
 * */
static void check_time_interval() {
    const wm_aws *ptr = (wm_aws *) aws_module.data;
    time_t current = mktime(&test_aws_date_storage[0]);
    int i=1;
    while(i < MAX_DATES) {
        time_t next = mktime(&test_aws_date_storage[i]);
        assert_int_equal( ptr->scan_config.interval, next - current);
        current = mktime(&test_aws_date_storage[i++]);
    }
}

/**
 * Test that all executions matches day of the month configuration 
 * */
static void check_day_of_month() {
    const wm_aws *ptr = (wm_aws *) aws_module.data;
    for (int i = 0; i < MAX_DATES; i++) {
        assert_int_equal( ptr->scan_config.scan_day, test_aws_date_storage[i].tm_mday);
        if(i > 0){
            // Assert that months are consecutives
            assert_int_equal((test_aws_date_storage[i-1].tm_mon + 1) % 12, test_aws_date_storage[i].tm_mon);
        }
    }
}

/**
 * Test that all executions matches day of the month configuration 
 * */
static void check_day_of_week() {
    const wm_aws *ptr = (wm_aws *) aws_module.data;
    for (int i = 0; i < MAX_DATES; i++) {
        assert_int_equal( ptr->scan_config.scan_wday, test_aws_date_storage[i].tm_wday);
        if(i > 0){
            // Assert there is one week difference
            assert_int_equal((test_aws_date_storage[i-1].tm_yday + 7) % 365, test_aws_date_storage[i].tm_yday);
        }
    }
}

/**
 * Test that all executions matches day of the month configuration 
 * */
static void check_time_of_day() {
    const wm_aws *ptr = (wm_aws *) aws_module.data;
    for (int i = 0; i < MAX_DATES; i++) {
        char ** parts = OS_StrBreak(':', ptr->scan_config.scan_time, 2);
        // Look for the particular hour
        int tm_hour = atoi(parts[0]);
        int tm_min = atoi(parts[1]);
        
        assert_int_equal( tm_hour, test_aws_date_storage[i].tm_hour);
        assert_int_equal( tm_min, test_aws_date_storage[i].tm_min);
        if(i > 0){
            // Assert that there are following days
            assert_int_equal((test_aws_date_storage[i-1].tm_yday + 1) % 365, test_aws_date_storage[i].tm_yday);
        }
    }
}


/****************************************************************/

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<interval>10m</interval>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
}

void test_day_of_month(){
    set_up_test(check_day_of_month);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<day>3</day>\n"
        "<time>0:00</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
}

void test_day_of_week(){
    set_up_test(check_day_of_week);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<wday>Sunday</wday>\n"
        "<time>0:00</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
}

void test_time_of_day(){
    set_up_test(check_time_of_day);
    const char *string = 
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    wm_aws_read(&lxml, nodes, &aws_module);
    aws_module.context->start( (wm_aws *) aws_module.data);
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
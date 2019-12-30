/**
 * Test corresponding to the scheduling capacities
 * described in 'headers/schedule_scan.h' and 
 * 'shared/schedule_scan.c' files
 * 
 * To add this tests on CMAKE:
 *  
 *  list(APPEND tests_names "test_wmodules_scheduling")
 *  list(APPEND tests_flags "-Wl,--wrap=time,--wrap=wm_delay,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror")
 * 
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"

static const int TEST_INTERVAL = 5 * 60;
static const int TEST_DELAY    = 5;
static const int TEST_DAY_MONTHS[] =  {3, 8, 15, 21};

/**     Mocked functions       **/
static time_t current_time = 0;

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

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

/****************************/

static const XML_NODE string_to_xml_node(const char * string){
    OS_XML _lxml;
    XML_NODE nodes;
    OS_ReadXMLString(string, &_lxml);
    nodes = OS_GetElementsbyNode(&_lxml, NULL);
    return nodes;
}

static sched_scan_config init_config_from_string(const char* string){
    XML_NODE nodes = string_to_xml_node(string);

    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    sched_scan_read(&scan_config, nodes, "");

    return scan_config;
}

/**
 * Test caclulated time for an INTERVAL with a sleep in 
 * between
 * */
static void test_interval_mode(void **state){  
    const char *string =
        "<interval>5m</interval>"
    ;
    sched_scan_config scan_config = init_config_from_string(string);

    time_t next_time = sched_scan_get_next_time(&scan_config, "TEST_INTERVAL_MODE", 0);
    // First time
    assert_int_equal((int) next_time, 0);
    // Sleep 5 secs
    wm_delay(1000 * TEST_DELAY);
    next_time = sched_scan_get_next_time(&scan_config, "TEST_INTERVAL_MODE", 0);
    assert_int_equal((int) next_time, TEST_INTERVAL - TEST_DELAY);
}


/**
 * Test day of the month mode for different day values
 * */
static void test_day_of_the_month_mode(void **state){
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);

    // Set day of the month
    scan_config.month_interval = true;
    scan_config.interval = 1;
    scan_config.scan_time = strdup("00:00");

    for(int i = 0; i < (sizeof(TEST_DAY_MONTHS)/ sizeof(int)); i++){
        scan_config.scan_day = TEST_DAY_MONTHS[i];

        time_t time_sleep = sched_scan_get_next_time(&scan_config, "TEST_DAY_MONTH_MODE", 0); 
        time_t next_time = time(NULL) + time_sleep;

        struct tm *date = localtime(&next_time);
        // Assert execution time is the expected month day
        assert_int_equal(date->tm_mday,  TEST_DAY_MONTHS[i]);
    }
    
}

/**
 * Test 2 consecutive day of the month
 * */
static void test_day_of_the_month_consecutive(void **state){
    const char *string =
        "<day>20</day>\n"
        "<time>0:00</time>"
    ;
    sched_scan_config scan_config = init_config_from_string(string);

    time_t time_sleep = sched_scan_get_next_time(&scan_config, "TEST_DAY_MONTH_MODE", 0); 
    time_t first_time = time(NULL) + time_sleep;

    struct tm first_date = *(localtime(&first_time));
    // Assert execution time is the expected month day
    assert_int_equal(first_date.tm_mday,  scan_config.scan_day);

    // Sleep past execution moment by 1 hour
    wm_delay((time_sleep + 3600) * 1000);

    time_sleep = sched_scan_get_next_time(&scan_config, "TEST_DAY_MONTH_MODE", 0); 
    time_t second_time = time(NULL) + time_sleep;

    struct tm second_date = *(localtime(&second_time));

    assert_int_equal(second_date.tm_mday, scan_config.scan_day);
    // Check it is following month
    assert_int_equal((first_date.tm_mon + 1) % 12, second_date.tm_mon);

}

/**
 * Test 1 day of the week
 * */
static void test_day_of_the_week(void **state){
    const char *string =
        "<wday>tuesday</wday>\n"
        "<time>0:00</time>"
    ;
    sched_scan_config scan_config = init_config_from_string(string);

    time_t time_sleep = sched_scan_get_next_time(&scan_config, "TEST_WDAY_MODE", 0); 
    // Sleep past execution moment by 1 hour
    wm_delay((time_sleep + 3600) * 1000);

    time_t first_time = time(NULL);
    struct tm first_date = *(localtime(&first_time));

    assert_int_equal(first_date.tm_wday,  scan_config.scan_wday);

    time_sleep = sched_scan_get_next_time(&scan_config, "TEST_WDAY_MODE", 0); 
    time_t second_time = time(NULL) + time_sleep;

    struct tm second_date = *(localtime(&second_time));
    assert_int_equal(second_date.tm_wday,  scan_config.scan_wday);

    assert_int_not_equal(first_date.tm_yday, second_date.tm_yday);
}

/**
 * Test time of day execution
 * */
static void test_time_of_day(void **state){
    const char *string =
        "<time>5:18</time>"
    ;
    sched_scan_config scan_config = init_config_from_string(string);
    time_t time_sleep = sched_scan_get_next_time(&scan_config, "TEST_WDAY_MODE", 0); 
    wm_delay(time_sleep * 1000);

    time_t current_time = time(NULL);
    struct tm date = *(localtime(&current_time));

    assert_int_equal(date.tm_hour, 5);
    assert_int_equal(date.tm_min, 18);
}

/**
 * Test Parsing and dumping of configurations
 * */
static void test_parse_xml_and_dump(void **state){
    const char *string = 
    "<wday>friday</wday>\n"
    "<time>13:14</time>";
    sched_scan_config scan_config = init_config_from_string(string);
    cJSON *data = cJSON_CreateObject();
    sched_scan_dump(&scan_config, data);
    assert_string_equal(cJSON_PrintUnformatted(data), "{\"interval\":604800,\"wday\":\"friday\",\"time\":\"13:14\"}");
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interval_mode),
        cmocka_unit_test(test_day_of_the_month_mode),
        cmocka_unit_test(test_day_of_the_month_consecutive),
        cmocka_unit_test(test_day_of_the_week),
        cmocka_unit_test(test_time_of_day),
        cmocka_unit_test(test_parse_xml_and_dump)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

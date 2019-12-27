/**
 * Test corresponding to the scheduling capacities
 * described in 'headers/schedule_scan.h' and 
 * 'shared/schedule_scan.c' files
 * 
 * To add this tests on CMAKE:
 *  
 *  list(APPEND tests_names "test_wmodules_scheduling")
 *  list(APPEND tests_flags "-Wl,--wrap=time,--wrap=wm_delay")
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

/**
 * Test caclulated time for an INTERVAL with a sleep in 
 * between
 * */
static void test_interval_mode(void **state){  
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);

    // Set 5 min interval
    scan_config.interval = TEST_INTERVAL;

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
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);

    // Set day of the month
    scan_config.month_interval = true;
    scan_config.interval = 1;
    scan_config.scan_time = strdup("00:00");
    scan_config.scan_day = TEST_DAY_MONTHS[0];

    time_t time_sleep = sched_scan_get_next_time(&scan_config, "TEST_DAY_MONTH_MODE", 0); 
    time_t first_time = time(NULL) + time_sleep;

    struct tm first_date = *(localtime(&first_time));
    // Assert execution time is the expected month day
    assert_int_equal(first_date.tm_mday,  TEST_DAY_MONTHS[0]);

    // Sleep past execution moment by 1 hour
    wm_delay(time_sleep + (3600 * 1000));

    time_sleep = sched_scan_get_next_time(&scan_config, "TEST_DAY_MONTH_MODE", 0); 
    time_t second_time = time(NULL) + time_sleep;

    struct tm second_date = *(localtime(&second_time));

    assert_int_equal(second_date.tm_mday,  TEST_DAY_MONTHS[0]);
    // Check it is following month
    assert_int_equal((first_date.tm_mon + 1) % 12, second_date.tm_mon);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interval_mode),
        cmocka_unit_test(test_day_of_the_month_mode),
        cmocka_unit_test(test_day_of_the_month_consecutive)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/**
 * Unitary test for methods 
 * described in 'headers/schedule_scan.h' and 
 * 'shared/schedule_scan.c' files
* */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"

static time_t current_time = 0;

extern time_t _get_next_time(const sched_scan_config *config, const char *MODULE_TAG,  const int run_on_start);
extern int _sched_scan_validate_parameters(sched_scan_config *scan_config);
extern time_t __real_time(time_t *_time);

typedef struct test_structure {
    xml_node **nodes;
    sched_scan_config *scan_config;
} test_structure;
/*********************************/
/*       WRAPS                   */ 
/*********************************/
int __wrap_OS_StrIsNum(const char *str) {
    int retval = mock();

    check_expected(str);

    return retval;
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_check_day_to_scan(int day, const char *hour) {
    check_expected(day);
    check_expected(hour);
    return mock();
}

int __wrap_get_time_to_hour(const char * hour) {
    check_expected(hour);
    return mock();
}

int __wrap_get_time_to_day(int wday, const char * hour) {
    check_expected(wday);
    check_expected(hour);
    return mock();
}

time_t __wrap_time(time_t *_time){
    if(!current_time){
        current_time = __real_time(NULL);
    }
    return current_time;
}

void __wrap_wm_delay(unsigned int msec){
    current_time += (msec/1000);
}
/*********************************/
/*       SETUP-TEARDOWN          */
/*********************************/
static int test_scan_read_setup(void **state) {
    test_structure *test; 
    os_calloc(1, sizeof(test_structure), test);
    xml_node **nodes;
    os_calloc(2, sizeof(xml_node*), nodes);
    os_calloc(1, sizeof(xml_node), nodes[0]);
    test->nodes = nodes;
    os_calloc(1, sizeof(sched_scan_config), test->scan_config);
    *state = test;
    return 0;
}

static int test_scan_read_teardown(void **state) {
    test_structure *test = ( test_structure *) *state; 
    os_free(test->nodes[0]->element);
    os_free(test->nodes[0]->content);
    os_free(test->nodes[0]);
    os_free(test->nodes);
    os_free(test->scan_config->scan_time);
    os_free(test->scan_config);
    os_free(test);
    return 0;
}

/*********************************/
/*       TESTS                   */
/*********************************/
void test_tag_successfull(void **state) {
    assert_int_equal(is_sched_tag("interval"), 1);
    assert_int_equal(is_sched_tag("day"), 1);
    assert_int_equal(is_sched_tag("wday"), 1);
    assert_int_equal(is_sched_tag("time"), 1);
}

void test_tag_failure(void **state) {
    assert_int_equal(is_sched_tag("foo"), 0);
    assert_int_equal(is_sched_tag("bar"), 0);
    assert_int_equal(is_sched_tag("parrot"), 0);
    assert_int_equal(is_sched_tag("fake_tag"), 0);
} 

void test_sched_scan_init(void **state){
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    assert_int_equal(scan_config.scan_wday, -1);
    assert_int_equal(scan_config.scan_day, 0);
    assert(scan_config.scan_time == NULL);
    assert_int_equal(scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(scan_config.month_interval,false);
    assert_int_equal(scan_config.time_start, 0);
    assert_int_equal(scan_config.last_scan_time, 0);
}

void test_sched_scan_read_correct_day(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("15");
    expect_string(__wrap_OS_StrIsNum, str,  "15");
    will_return(__wrap_OS_StrIsNum, 1);
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->scan_day, 15);
}

void test_sched_scan_read_wrong_day(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("123");
    expect_string(__wrap_OS_StrIsNum, str,  "123");
    will_return(__wrap_OS_StrIsNum, 1);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'day': 123.");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_not_number(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("abc");
    expect_string(__wrap_OS_StrIsNum, str,  "abc");
    will_return(__wrap_OS_StrIsNum, 0);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'day': abc.");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_correct_wday(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("wday");
    nodes[0]->content = strdup("Monday");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->scan_wday, 1);
}

void test_sched_scan_read_wrong_wday(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("wday");
    nodes[0]->content = strdup("UnexistentDay");
    expect_string(__wrap__merror, formatted_msg, "(1241): Invalid day format: 'UnexistentDay'.");
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'wday': UnexistentDay.");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_correct_time(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("time");
    nodes[0]->content = strdup("12:30");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_string_equal(test->scan_config->scan_time, nodes[0]->content);
}

void test_sched_scan_read_wrong_time(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("time");
    nodes[0]->content = strdup("aa:40");
    expect_string(__wrap__merror, formatted_msg, "(1240): Invalid time format: 'aa:40'.");
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'time': aa:40.");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_correct_interval_month(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("2M");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->interval, 2);
    assert_int_equal(test->scan_config->month_interval, true);
}

void test_sched_scan_read_correct_interval_week(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("5w");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->interval, 5*604800);
    assert_int_equal(test->scan_config->month_interval, false);
}

void test_sched_scan_read_correct_interval_day(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("2d");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->interval, 2*86400);
    assert_int_equal(test->scan_config->month_interval, false);
}

void test_sched_scan_read_correct_interval_hour(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("1h");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->interval, 3600);
    assert_int_equal(test->scan_config->month_interval, false);
}

void test_sched_scan_read_correct_interval_minute(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("25m");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->interval, 25*60);
    assert_int_equal(test->scan_config->month_interval, false);
}

void test_sched_scan_read_correct_interval_second(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("100s");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(test->scan_config->interval, 100);
    assert_int_equal(test->scan_config->month_interval, false);
}

void test_sched_scan_read_wrong_interval(void **state) {
    test_structure *test = ( test_structure *) *state; 
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("interval");
    nodes[0]->content = strdup("three seconds");
    expect_string(__wrap__merror, formatted_msg, "Invalid interval value at module 'TEST_MODULE'");
    int ret = sched_scan_read(test->scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_validate_incompatible_wday(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_day = 1;
    scan_config.scan_wday = 1;
    expect_string(__wrap__merror, formatted_msg, "Options 'day' and 'wday' are not compatible.");
    int ret = _sched_scan_validate_parameters(&scan_config);
    assert_int_equal(ret, -1);
    os_free(scan_config.scan_time);
}

void test_sched_scan_validate_day_not_month_interval(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_day = 1;
    scan_config.month_interval = false;
    scan_config.scan_time = NULL;
    int ret = _sched_scan_validate_parameters(&scan_config);
    assert_int_equal(scan_config.month_interval, true);
    assert_int_equal(scan_config.interval, 1);
    assert_string_equal(scan_config.scan_time, "00:00");
    assert_int_equal(ret, 0);
    os_free(scan_config.scan_time);
}

void test_sched_scan_validate_wday_not_week_interval(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_wday = 2;
    scan_config.interval = 7;
    scan_config.scan_time = NULL;
    int ret = _sched_scan_validate_parameters(&scan_config);
    assert_int_equal(scan_config.scan_wday, 2);
    assert_int_equal(scan_config.interval, 604800);
    assert_string_equal(scan_config.scan_time, "00:00");
    assert_int_equal(ret, 0);
    os_free(scan_config.scan_time);
}

void test_sched_scan_validate_time_not_day_interval(void **state){
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_time = strdup("00:00");
    scan_config.interval = 30;
    int ret = _sched_scan_validate_parameters(&scan_config);
    assert_int_equal(scan_config.interval, WM_DEF_INTERVAL);
    assert_string_equal(scan_config.scan_time, "00:00");
    assert_int_equal(ret, 0);
    os_free(scan_config.scan_time);
}

void test_get_next_time_day_configuration(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_day = 1;
    scan_config.month_interval = true;
    scan_config.interval = 2; //Each 2 months
    scan_config.scan_time = strdup("00:00");
    expect_value_count(__wrap_check_day_to_scan, day, 1, 2);
    expect_string_count(__wrap_check_day_to_scan, hour, "00:00", 2);
    will_return_always(__wrap_check_day_to_scan, 0);
    expect_string_count(__wrap_get_time_to_hour, hour, "00:00", 2);
    will_return(__wrap_get_time_to_hour, 0);
    will_return(__wrap_get_time_to_hour, 5);
    time_t ret = _get_next_time(&scan_config, "TEST_MODULE", 0);
    assert_int_equal((int)ret, 5);
    os_free(scan_config.scan_time);
}


void test_get_next_time_wday_configuration(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_wday = 2;
    scan_config.scan_time = strdup("00:00");
    expect_value(__wrap_get_time_to_day, wday, 2);
    expect_string(__wrap_get_time_to_day, hour, "00:00");
    will_return(__wrap_get_time_to_day, 15);
    time_t ret = _get_next_time(&scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, 15);
    os_free(scan_config.scan_time);
}

void test_get_next_time_daytime_configuration(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.scan_time = strdup("05:00");
    expect_string(__wrap_get_time_to_hour, hour, "05:00");
    will_return(__wrap_get_time_to_hour, 8);
    time_t ret = _get_next_time(&scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, 8);
    os_free(scan_config.scan_time);
}

void test_get_next_time_interval_configuration(void **sate) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    scan_config.interval = 3600;
    time_t ret = _get_next_time(&scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, 0); //First time in interval is on start
    scan_config.last_scan_time = time(NULL); // Update last scan time
    ret = _get_next_time(&scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, 3600);
    os_free(scan_config.scan_time);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tag_successfull),
        cmocka_unit_test(test_tag_failure),
        cmocka_unit_test(test_sched_scan_init),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_day, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_wrong_day, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_not_number, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_wday, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_wrong_wday, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_time, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_wrong_time, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_interval_month, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_interval_week, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_interval_day, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_interval_hour, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_interval_minute, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_correct_interval_second, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_read_wrong_interval, test_scan_read_setup, test_scan_read_teardown),
        cmocka_unit_test(test_sched_scan_validate_incompatible_wday),
        cmocka_unit_test(test_sched_scan_validate_day_not_month_interval),
        cmocka_unit_test(test_sched_scan_validate_wday_not_week_interval),
        cmocka_unit_test(test_sched_scan_validate_time_not_day_interval),
        cmocka_unit_test(test_get_next_time_day_configuration),
        cmocka_unit_test(test_get_next_time_wday_configuration),
        cmocka_unit_test(test_get_next_time_daytime_configuration),
        cmocka_unit_test(test_get_next_time_interval_configuration)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
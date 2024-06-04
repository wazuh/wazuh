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
#include "../wazuh_modules/wmodules.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../wrappers/wazuh/os_regex/os_regex_wrappers.h"


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

time_t __wrap_time(time_t *_time){
    if(!current_time){
        current_time = __real_time(NULL);
    }
    return current_time;
}

/*********************************/
/*       SETUP-TEARDOWN          */
/*********************************/
static int test_scan_read_setup(void **state) {
    test_structure *test;
    test = calloc(1, sizeof(test_structure));
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));
    test->nodes = nodes;
    test->scan_config = calloc(1, sizeof(sched_scan_config));
    *state = test;
    return 0;
}

static int test_scan_read_teardown(void **state) {
    test_structure *test = ( test_structure *) *state;
    free(test->nodes[0]->element);
    free(test->nodes[0]->content);
    free(test->nodes[0]);
    free(test->nodes);
    if(test->scan_config->scan_time)
        free(test->scan_config->scan_time);
    free(test->scan_config);
    free(test);
    return 0;
}

static int test_sched_scan_validate_setup(void **state) {
    sched_scan_config *scan_config;
    scan_config = calloc(1, sizeof(sched_scan_config));
    sched_scan_init(scan_config);
    *state = scan_config;
    return 0;
}

static int test_sched_scan_validate_teardown(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    sched_scan_free(scan_config);
    free(scan_config);
    return 0;
}

static int test_get_time_setup(void **state) {
    current_time = 1591189200;
    return 0;
}

static int test_get_time_teardown(void **state) {
    current_time = 0;
    return 0;
}

static int setup_group(void **state) {
    current_time = 0;
    return 0;
}

static int teardown_group(void **state) {
    current_time = 0;
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
    assert_int_equal(scan_config.next_scheduled_scan_time, 0);
}

void test_sched_scan_read_correct_day(void **state) {
    test_structure *test = ( test_structure *) *state;
    sched_scan_init(test->scan_config);
    xml_node **nodes = test->nodes;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("15");
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M" );
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
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w" );
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
    expect_string(__wrap__mwarn, formatted_msg, "Interval value is in months. Setting scan day to first day of the month." );
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
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->scan_day = 1;
    scan_config->scan_wday = 1;
    expect_string(__wrap__merror, formatted_msg, "Options 'day' and 'wday' are not compatible.");
    int ret = _sched_scan_validate_parameters(scan_config);
    assert_int_equal(ret, -1);
}

void test_sched_scan_validate_day_not_month_interval(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    scan_config->scan_day = 1;
    scan_config->month_interval = false;
    scan_config->scan_time = NULL;
    int ret = _sched_scan_validate_parameters(scan_config);
    assert_int_equal(scan_config->month_interval, true);
    assert_int_equal(scan_config->interval, 1);
    assert_string_equal(scan_config->scan_time, "00:00");
    assert_int_equal(ret, 0);
}

void test_sched_scan_validate_wday_not_week_interval(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    scan_config->scan_wday = 2;
    scan_config->interval = 7;
    scan_config->scan_time = NULL;
    int ret = _sched_scan_validate_parameters(scan_config);
    assert_int_equal(scan_config->scan_wday, 2);
    assert_int_equal(scan_config->interval, 604800);
    assert_string_equal(scan_config->scan_time, "00:00");
    assert_int_equal(ret, 0);
}

void test_sched_scan_validate_time_not_day_interval(void **state){
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    scan_config->scan_time = strdup("00:00");
    scan_config->interval = 30;
    int ret = _sched_scan_validate_parameters(scan_config);
    assert_int_equal(scan_config->interval, WM_DEF_INTERVAL);
    assert_string_equal(scan_config->scan_time, "00:00");
    assert_int_equal(ret, 0);
}

void test_get_next_time_day_configuration(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->scan_day = 1;
    scan_config->month_interval = true;
    scan_config->interval = 2; //Each 2 months
    scan_config->scan_time = strdup("00:00");
    time_t ret = _get_next_time(scan_config, "TEST_MODULE", 0);
    assert_int_equal((int)ret, get_time_to_month_day(1, "00:00", 2));
}


void test_get_next_time_wday_configuration(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->scan_wday = 2;
    scan_config->scan_time = strdup("00:00");
    time_t ret = _get_next_time(scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, get_time_to_day(2, "00:00", 1, true));
}

void test_get_next_time_daytime_configuration(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->scan_time = strdup("05:00");
    time_t ret = _get_next_time(scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, get_time_to_hour("05:00", 1, true));
}

void test_get_next_time_interval_configuration(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->interval = 3600;
    time_t ret = _get_next_time(scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, 3600);
    scan_config->next_scheduled_scan_time = time(NULL); // Update last scan time
    ret = _get_next_time(scan_config, "TEST_MODULE", 0);
    assert_int_equal((int) ret, 3600);
}

void test_sched_scan_dump_day(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    cJSON * object = cJSON_CreateObject();
    char * object_str = NULL;

    scan_config->scan_day = 3;
    scan_config->scan_time = "08:00";
    scan_config->interval = WM_DEF_INTERVAL;
    sched_scan_dump(scan_config, object);
    object_str = cJSON_PrintUnformatted(object);

    assert_string_equal(object_str, "{\"interval\":86400,\"day\":3,\"time\":\"08:00\"}");

    cJSON_Delete(object);
    os_free(object_str);
    os_free(scan_config);
}

void test_sched_scan_dump_wday(void **state) {
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    char * object_str = NULL;
    cJSON * wday;
    int i;

    char * week_days[] = {"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"};

    for (i = 0; i < 7; i++) {
        cJSON * object = cJSON_CreateObject();
        scan_config->scan_wday = i;
        sched_scan_dump(scan_config, object);
        wday = cJSON_GetObjectItem(object, "wday");
        assert_string_equal(week_days[i], wday->valuestring);
        cJSON_Delete(object);
    }

    os_free(scan_config);
}

void test_check_daylight_first_time(void **state) {
    (void) state;
    time_t next_scan_time = 0;
    time_t next_scan_time_initial = next_scan_time;
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->daylight = -1;

    check_daylight(scan_config, &next_scan_time, false);
    assert_int_equal(next_scan_time, next_scan_time_initial + 0);
}

void test_check_daylight_same_daylight_zero(void **state) {
    (void) state;
    time_t next_scan_time = 0;
    time_t next_scan_time_initial = next_scan_time;
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->daylight = 0;

    check_daylight(scan_config, &next_scan_time, false);
    assert_int_equal(next_scan_time, next_scan_time_initial + 0);
}

void test_check_daylight_same_daylight_one(void **state) {
    (void) state;
    time_t next_scan_time = 0;
    time_t next_scan_time_initial = next_scan_time;
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->daylight = 1;

    check_daylight(scan_config, &next_scan_time, true);
    assert_int_equal(next_scan_time, next_scan_time_initial + 0);
}

void test_check_daylight_different_daylight_one_zero(void **state) {
    (void) state;
    time_t next_scan_time = 0;
    time_t next_scan_time_initial = next_scan_time;
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->daylight = 1;

    check_daylight(scan_config, &next_scan_time, false);
    assert_int_equal(next_scan_time, next_scan_time_initial + 3600);
}

void test_check_daylight_different_daylight_zero_one(void **state) {
    (void) state;
    time_t next_scan_time = 0;
    time_t next_scan_time_initial = next_scan_time;
    sched_scan_config *scan_config = (sched_scan_config *)  *state;
    scan_config->daylight = 0;

    check_daylight(scan_config, &next_scan_time, true);
    assert_int_equal(next_scan_time, next_scan_time_initial - 3600);
}

void test_get_time_to_hour_no_negative_diff(void **state) {
    /* Date: Mon 2020/06/03 15:00:00 */
    char hour[6];
    const unsigned int num_days = 1;
    bool first_time = true;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time + 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    diff_test = get_time_to_hour(hour, num_days, first_time);

    assert_int_equal(diff_test, 60);
}

void test_get_time_to_hour_first_time(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    char hour[6];
    const unsigned int num_days = 1;
    bool first_time = true;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time - 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    diff_test = get_time_to_hour(hour, num_days, first_time);

    assert_int_equal(diff_test, 3600*24-60);
}

void test_get_time_to_hour_num_days(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    char hour[6];
    const unsigned int num_days = 3;
    bool first_time = false;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time - 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    diff_test = get_time_to_hour(hour, num_days, first_time);

    assert_int_equal(diff_test, num_days*3600*24-60);
}

void test_get_time_to_day_same_wday_positive_diff(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int wday;
    char hour[6];
    const unsigned int num_weeks = 1;
    bool first_time = true;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time + 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    wday = current_tm.tm_wday;
    diff_test = get_time_to_day(wday, hour, num_weeks, first_time);

    assert_int_equal(diff_test, 60);
}

void test_get_time_to_day_same_wday_negative_diff_first_time(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int wday;
    char hour[6];
    const unsigned int num_weeks = 1;
    bool first_time = true;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time - 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    wday = current_tm.tm_wday;
    diff_test = get_time_to_day(wday, hour, num_weeks, first_time);

    assert_int_equal(diff_test, 3600*24*7-60);
}

void test_get_time_to_day_same_wday_negative_diff_num_weeks(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int wday;
    char hour[6];
    const unsigned int num_weeks = 3;
    bool first_time = false;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time - 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    wday = current_tm.tm_wday;
    diff_test = get_time_to_day(wday, hour, num_weeks, first_time);

    assert_int_equal(diff_test, num_weeks*3600*24*7-60);
}

void test_get_time_to_day_different_before_wday(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int wday;
    char hour[6];
    const unsigned int num_weeks = 1;
    bool first_time = true;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time + 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    wday = current_tm.tm_wday + 2;
    diff_test = get_time_to_day(wday, hour, num_weeks, first_time);

    assert_int_equal(diff_test, 60+3600*24*(wday-current_tm.tm_wday));
}

void test_get_time_to_day_different_after_wday(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int wday;
    char hour[6];
    const unsigned int num_weeks = 1;
    bool first_time = true;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time + 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    wday = current_tm.tm_wday - 2;
    diff_test = get_time_to_day(wday, hour, num_weeks, first_time);

    assert_int_equal(diff_test, 60+3600*24*(7-(current_tm.tm_wday-wday)));
}

void test_get_time_to_month_day_same_month_day_positive_diff(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int mday;
    char hour[6];
    const unsigned int num_months = 1;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time + 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    mday = current_tm.tm_mday;
    diff_test = get_time_to_month_day(mday, hour, num_months);

    assert_int_equal(diff_test, 60);
}

void test_get_time_to_month_day_same_month(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int mday;
    char hour[6];
    const unsigned int num_months = 1;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time + 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    mday = current_tm.tm_mday + 1;
    diff_test = get_time_to_month_day(mday, hour, num_months);

    assert_int_equal(diff_test, 3600*24+60);
}

void test_get_time_to_month_day_high_num_months(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int mday;
    char hour[6];
    const unsigned int num_months = 13;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time - 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    mday = current_tm.tm_mday;
    diff_test = get_time_to_month_day(mday, hour, num_months);

    assert_int_equal(diff_test, 3600*24*395-60);
}

void test_get_time_to_month_day_num_months(void **state) {
    /* Date: Wed 2020/06/03 15:00:00 */
    int mday;
    char hour[6];
    const unsigned int num_months = 8;
    unsigned long diff_test;
    time_t diff_time;
    struct tm current_tm;

    diff_time = current_time - 60;
    localtime_r(&diff_time, &current_tm);
    sprintf(hour, "%2d:%2d", current_tm.tm_hour, current_tm.tm_min);
    mday = current_tm.tm_mday;
    diff_test = get_time_to_month_day(mday, hour, num_months);

    assert_int_equal(diff_test, 3600*24*245-60);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tag_successfull),
        cmocka_unit_test(test_tag_failure),
        cmocka_unit_test(test_sched_scan_init),
        /* sched_scan_read function tests */
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
        /* _sched_scan_validate_parameters function tests */
        cmocka_unit_test_setup_teardown(test_sched_scan_validate_incompatible_wday, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_validate_day_not_month_interval, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_validate_wday_not_week_interval, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_sched_scan_validate_time_not_day_interval, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        /* _get_next_time function tests */
        cmocka_unit_test_setup_teardown(test_get_next_time_day_configuration, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_get_next_time_wday_configuration, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_get_next_time_daytime_configuration, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_get_next_time_interval_configuration, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        /* sched_scan_dump function tests */
        cmocka_unit_test_setup(test_sched_scan_dump_day, test_sched_scan_validate_setup),
        cmocka_unit_test_setup(test_sched_scan_dump_wday, test_sched_scan_validate_setup),
        /* check_daylight function tests */
        cmocka_unit_test_setup_teardown(test_check_daylight_first_time, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_check_daylight_same_daylight_zero, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_check_daylight_same_daylight_one, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_check_daylight_different_daylight_one_zero, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        cmocka_unit_test_setup_teardown(test_check_daylight_different_daylight_zero_one, test_sched_scan_validate_setup, test_sched_scan_validate_teardown),
        /* get_time_to_hour function tests */
        cmocka_unit_test_setup_teardown(test_get_time_to_hour_no_negative_diff, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_hour_first_time, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_hour_num_days, test_get_time_setup, test_get_time_teardown),
        /* get_time_to_day function tests */
        cmocka_unit_test_setup_teardown(test_get_time_to_day_same_wday_positive_diff, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_day_same_wday_negative_diff_first_time, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_day_same_wday_negative_diff_num_weeks, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_day_different_before_wday, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_day_different_after_wday, test_get_time_setup, test_get_time_teardown),
        /* get_time_to_month_day function tests */
        cmocka_unit_test_setup_teardown(test_get_time_to_month_day_same_month_day_positive_diff, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_month_day_same_month, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_month_day_high_num_months, test_get_time_setup, test_get_time_teardown),
        cmocka_unit_test_setup_teardown(test_get_time_to_month_day_num_months, test_get_time_setup, test_get_time_teardown)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}

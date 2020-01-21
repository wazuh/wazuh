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
/*********************************/
/*       SETUP-TEARDOWN          */
/*********************************/
static int test_scan_read_setup(void **state) {
    xml_node **nodes;
    os_calloc(2, sizeof(xml_node*), nodes);
    os_calloc(1, sizeof(xml_node), nodes[0]);
    *state = nodes;
    return 0;
}

static int test_scan_read_teardown(void **state) {
    xml_node **nodes = (xml_node **)state;
    free(nodes[0]->element);
    free(nodes[0]->content);
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
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("15");
    expect_string(__wrap_OS_StrIsNum, str,  "15");
    will_return(__wrap_OS_StrIsNum, 1);
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(scan_config.scan_day, 15);
}

void test_sched_scan_read_wrong_day(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("123");
    expect_string(__wrap_OS_StrIsNum, str,  "123");
    will_return(__wrap_OS_StrIsNum, 1);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'day': 123.");
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_not_number(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("day");
    nodes[0]->content = strdup("abc");
    expect_string(__wrap_OS_StrIsNum, str,  "abc");
    will_return(__wrap_OS_StrIsNum, 0);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'day': abc.");
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_correct_wday(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("wday");
    nodes[0]->content = strdup("Monday");
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_int_equal(scan_config.scan_wday, 1);
}

void test_sched_scan_read_wrong_wday(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("wday");
    nodes[0]->content = strdup("UnexistentDay");
    expect_string(__wrap__merror, formatted_msg, "(1241): Invalid day format: 'UnexistentDay'.");
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'wday': UnexistentDay.");
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
}

void test_sched_scan_read_correct_time(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("time");
    nodes[0]->content = strdup("12:30");
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, 0);
    assert_string_equal(scan_config.scan_time, nodes[0]->content);
}

void test_sched_scan_read_wrong_time(void **state) {
    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    xml_node **nodes = (xml_node **)state;
    nodes[0]->element = strdup("time");
    nodes[0]->content = strdup("aa:40");
    expect_string(__wrap__merror, formatted_msg, "(1240): Invalid time format: 'aa:40'.");
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'time': aa:40.");
    int ret = sched_scan_read(&scan_config, nodes, "TEST_MODULE");
    assert_int_equal(ret, -1);
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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
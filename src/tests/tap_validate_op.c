#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../headers/validate_op.h"
#include "tap.h"


int test_getNetmask() {

    int ret = 0;
    char strmask[8];

    getNetmask(0, strmask, 8);
    if (strcmp(strmask, "/any") == 0) {
        ret++;
    }
    getNetmask(65535, strmask, 8);
    if (strcmp(strmask, "/16") == 0) {
        ret++;
    }
    getNetmask(16777215, strmask, 8);
    if (strcmp(strmask, "/24") == 0) {
        ret++;
    }
    getNetmask(-1, strmask, 8);
    if (strcmp(strmask, "/32") == 0) {
        ret++;
    }
    if (ret == 4) {
        return 1;
    }
    return 0;
}


int test_OS_IPFound() {
    int ret = 0;
    char test_ip[] = "192.168.1.1/16";
    os_ip *test_os_ip = malloc(sizeof(os_ip));
    OS_IsValidIP(test_ip, test_os_ip);
    if (OS_IPFound("192.168.1.0", test_os_ip)) {
        ret++;
    }
    if (OS_IPFound("192.168.1.254", test_os_ip)) {
        ret++;
    }
    if (OS_IPFound("192.168.2.254", test_os_ip)) {
        ret++;
    }
    if (OS_IPFound("192.168.254.254", test_os_ip)) {
        ret++;
    }
    if (!OS_IPFound("192.169.1.1", test_os_ip)) {
        ret++;
    }
    if (!OS_IPFound("192.169.254.254", test_os_ip)) {
        ret++;
    }
    if (!OS_IPFound("192.0.0.1", test_os_ip)) {
        ret++;
    }
    free(test_os_ip->ip);
    free(test_os_ip);
    return (ret == 7);
}


int test_OS_IPFoundList() {
    int ret = 0;
    char test_ip_1[] = "192.168.1.1/8";
    char test_ip_2[] = "10.0.1.1/24";
    os_ip **test_os_ip = malloc(2 * sizeof(os_ip*));
    test_os_ip[0] = malloc(sizeof(os_ip));
    test_os_ip[1] = malloc(sizeof(os_ip));
    OS_IsValidIP(test_ip_1, test_os_ip[0]);
    OS_IsValidIP(test_ip_2, test_os_ip[1]);
    if (OS_IPFoundList("192.168.1.14", test_os_ip)) {
        ret += 1;
    }
    if (OS_IPFoundList("10.0.1.254", test_os_ip)) {
        ret += 1;
    }
    if (OS_IPFoundList("192.168.1.254", test_os_ip)) {
        ret += 1;
    }
    if (OS_IPFoundList("192.168.254.254", test_os_ip)) {
        ret += 1;
    }
    if (OS_IPFoundList("192.169.1.1", test_os_ip)) {
        ret += 1;
    }
    if (OS_IPFoundList("192.169.254.254", test_os_ip)) {
        ret += 1;
    }
    if (OS_IPFoundList("192.0.0.1", test_os_ip)) {
        ret += 1;
    }
    int i;
    for (i = 0; i < 2; i++) {
        free(test_os_ip[i]->ip);
        free(test_os_ip[i]);
    }
    free(test_os_ip);
    return (ret == 7);
}


int test_OS_IsValidIP() {
    int ret = 0;
    char test_ip[] = "192.168.1.1/16";
    os_ip *test_os_ip = malloc(sizeof(os_ip));
    if (OS_IsValidIP(test_ip, test_os_ip)) {
        ret = 1;
    }
    free(test_os_ip->ip);
    free(test_os_ip);
    return ret;
}


int test_OS_IsValidIP_nok() {
    int ret = 0;
    char test_ip[] = "192.168.1.356/24";
    os_ip *test_os_ip = malloc(sizeof(os_ip));
    if (OS_IsValidIP(test_ip, test_os_ip) == 0) {
        ret = 1;
    }
    free(test_os_ip->ip);
    free(test_os_ip);
    return ret;
}


int check_OS_IsValidTime(const char *time_str) {
    char *time = strdup(time_str);
    char *valid;
    if (valid = OS_IsValidTime(time), valid) {
        free(valid);
        free(time);
        return 1;
    }
    free(time);
    return 0;
}


int test_OS_IsValidTime() {
    int ret = 0;
    if (check_OS_IsValidTime("12:00-18:00")) {
        ret++;
    }
    if (check_OS_IsValidTime("!12:00-23:00")) {
        ret++;
    }
    if (check_OS_IsValidTime("12:00-00:00")) {
        ret++;
    }
    if (check_OS_IsValidTime("00:00-12:00")) {
        ret++;
    }
    if (check_OS_IsValidTime("21 - 23")) {
        ret++;
    }
    if (check_OS_IsValidTime("12:00 am - 10:00 pm")) {
        ret++;
    }
    if (check_OS_IsValidTime("9 pm - 18:00")) {
        ret++;
    }
    if (check_OS_IsValidTime("11:59 pm - 12 am")) {
        ret++;
    }
    if (check_OS_IsValidTime("07 pm - 22:00")) {
        ret++;
    }
    if (!check_OS_IsValidTime("9 pm - 24 am")) {
        ret++;
    }
    if (!check_OS_IsValidTime("12:00 pm - 12 am")) {
        ret++;
    }
    if (!check_OS_IsValidTime("24:00 - 22:00")) {
        ret++;
    }
    return (ret == 12);
}


int check_OS_IsValidUniqueTime(const char *time_str) {
    char *time = strdup(time_str);
    char *valid;
    if (valid = OS_IsValidUniqueTime(time), valid) {
        free(valid);
        free(time);
        return 1;
    }
    free(time);
    return 0;
}


int test_OS_IsValidUniqueTime() {
    int ret = 0;
    if (check_OS_IsValidUniqueTime("12:00")) {
        ret++;
    }
    if (check_OS_IsValidUniqueTime("12 am")) {
        ret++;
    }
    if (!check_OS_IsValidUniqueTime("13:00 pm")) {
        ret++;
    }
    if (!check_OS_IsValidUniqueTime("25:00")) {
        ret++;
    }
    if (check_OS_IsValidUniqueTime("0")) {
        ret++;
    }
    if (!check_OS_IsValidUniqueTime("26")) {
        ret++;
    }
    if (!check_OS_IsValidUniqueTime("12:00 pm")) {
        ret++;
    }
    if (check_OS_IsValidUniqueTime("12:00 am")) {
        ret++;
    }
    return (ret == 8);
}


int test_OS_IsonTime() {
    char time[] = "17:00-17:00";
    char interval[] = "12:00-22:00";
    return (OS_IsonTime(OS_IsValidTime(time), OS_IsValidTime(interval)));
}


int test_OS_IsAfterTime() {
    char time[] = "23:01-23:01";
    char interval[] = "12:00-22:00";
    return (OS_IsAfterTime(OS_IsValidTime(time), OS_IsValidTime(interval)));
}


int check_OS_IsValidDay(const char *day_str) {
    char *day = strdup(day_str);
    char *valid;
    if (valid = OS_IsValidDay(day), valid) {
        free(valid);
        free(day);
        return 1;
    }
    free(day);
    return 0;
}


int test_OS_IsValidDay() {
    int ret = 0;
    if (check_OS_IsValidDay("monday, wednesday")) {
        ret++;
    }
    if (check_OS_IsValidDay("monday, wednesday tuesday")) {
        ret++;
    }
    if (check_OS_IsValidDay("weekdays")) {
        ret++;
    }
    if (check_OS_IsValidDay("mon tue wed thu fri sat sun")) {
        ret++;
    }
    if (check_OS_IsValidDay("mon,tue,wed,thu,fri,sat,sun")) {
        ret++;
    }
    if (!check_OS_IsValidDay("")) {
        ret++;
    }
    if (check_OS_IsValidDay("mon tuesday, sunday")) {
        ret++;
    }
    if (check_OS_IsValidDay("weekends")) {
        ret++;
    }
    if (!check_OS_IsValidDay("mon sa")) {
        ret++;
    }
    if (check_OS_IsValidDay("  wed")) {
        ret++;
    }

    return (ret == 10);
}


int test_OS_IsonDay() {
    int ret = 0;
    char *day = NULL;
    if ((day = OS_IsValidDay("mon"), day) && OS_IsonDay(1, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("sun,wed"), day) && OS_IsonDay(0, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("mon,wed"), day) && OS_IsonDay(3, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("weekends"), day) && OS_IsonDay(6, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("weekends"), day) && !OS_IsonDay(5, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("weekdays"), day) && !OS_IsonDay(0, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("weekdays"), day) && OS_IsonDay(1, day)) {
        ret++;
        free(day);
    }
    if ((day = OS_IsValidDay("mon,tue,wed,thu,fri,sat"), day) && !OS_IsonDay(0, day)) {
        ret++;
        free(day);
    }
    return (ret == 8);
}


int test_OS_CIDRtoStr() {
    int ret = 0;
    char test_ip[] = "192.168.0.1/24";
    os_ip *test_os_ip = malloc(sizeof(os_ip));
    char test_str[24] = {0};
    OS_IsValidIP(test_ip, test_os_ip);

    if (OS_CIDRtoStr(test_os_ip, test_str, 24)) {
        printf("%s - %s\n", test_ip, test_str);
        goto exit;
    }
    printf("%s - %s\a\n", test_ip, test_str);
    if (strcmp(test_ip, test_str) == 0) {
        ret = 1;
    }

exit:
    free(test_os_ip->ip);
    free(test_os_ip);
    return ret;
}


int test_w_validate_wday() {
    int ret = 0;
    if (w_validate_wday("sun") == 0) {
        ret++;
    }
    if (w_validate_wday("mon") == 1) {
        ret++;
    }
    if (w_validate_wday("tue") == 2) {
        ret++;
    }
    if (w_validate_wday("wed") == 3) {
        ret++;
    }
    if (w_validate_wday("thu") == 4) {
        ret++;
    }
    if (w_validate_wday("fri") == 5) {
        ret++;
    }
    if (w_validate_wday("sat") == 6) {
        ret++;
    }
    if (w_validate_wday("") == -1) {
        ret++;
    }
    return (ret == 8);
}


int test_w_validate_time() {
    int ret = 0;
    if (!w_validate_time("xx")) {
        ret++;
    }
    if (w_validate_time("00:00")) {
        ret++;
    }
    if (!w_validate_time("25:00")) {
        ret++;
    }
    if (!w_validate_time("00:60")) {
        ret++;
    }
    if (w_validate_time("01:02")) {
        ret++;
    }
    if (w_validate_time("20:2")) {
        ret++;
    }
    if (w_validate_time("8:00")) {
        ret++;
    }
    if (!w_validate_time("20:65")) {
        ret++;
    }
    return (ret == 8);
}


int test_w_validate_interval() {
    int ret = 0;
    if (w_validate_interval(259200, 0) == 0) {
        ret++;
    }
    if (w_validate_interval(259201, 0)) {
        ret++;
    }
    if (w_validate_interval(259201, 5) == -1) {
        ret++;
    }
    if (w_validate_interval(1814400, 1) == 0) {
        ret++;
    }
    if (w_validate_interval(1814401, 1)) {
        ret++;
    }
    if (w_validate_interval(1814400, 2) == -1) {
        ret++;
    }
    return (ret == 6);
}


int main(void) {

    printf("\n\n   STARTING TEST - VALIDATE_OP   \n\n");

    TAP_TEST_MSG(test_getNetmask(), "Test getNetmask().");

    TAP_TEST_MSG(test_OS_IPFound(), "Test OS_IPFound().");

    TAP_TEST_MSG(test_OS_IPFoundList(), "Test OS_IPFoundList().");

    TAP_TEST_MSG(test_OS_IsValidIP(), "Test OS_IsValidIP(): Check valid IP.");

    TAP_TEST_MSG(test_OS_IsValidIP_nok(), "Test OS_IsValidIP(): Check invalid IP");

    TAP_TEST_MSG(test_OS_IsValidTime(), "OS_IsValidTime().");

    TAP_TEST_MSG(test_OS_IsValidUniqueTime(), "OS_IsValidUniqueTime().");

    TAP_TEST_MSG(test_OS_IsonTime(), "OS_IsonTime().");

    TAP_TEST_MSG(test_OS_IsAfterTime(), "OS_IsAfterTime().");

    TAP_TEST_MSG(test_OS_IsValidDay(), "OS_IsValidDay().");

    TAP_TEST_MSG(test_OS_IsonDay(), "OS_IsonDay().");

    TAP_TEST_MSG(test_OS_CIDRtoStr(), "OS_CIDRtoStr().");

    TAP_TEST_MSG(test_w_validate_wday(), "w_validate_wday().");

    TAP_TEST_MSG(test_w_validate_time(), "w_validate_time().");

    TAP_TEST_MSG(test_w_validate_interval(), "w_validate_interval().");

    TAP_PLAN;
    TAP_SUMMARY;

    printf("\n   ENDING TEST - VALIDATE_OP   \n\n");
    return 0;

}

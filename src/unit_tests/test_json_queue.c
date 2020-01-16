/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../headers/shared.h"

int Handle_JQueue(file_queue *fileq, int flags) __attribute__((nonnull));

int __wrap__minfo()
{
    return 0;
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

FILE * __wrap_fopen(const char *__restrict __filename, const char *__restrict __modes) __wur
{
    return mock_type(FILE *);
}

int __wrap_fseek()
{
    return mock();
}

int __wrap_fstat()
{
    return mock();
}

void __wrap_fileno()
{
    return;
}

int __wrap_fclose(FILE *__stream)
{
    check_expected_ptr(__stream);

    return 0;
}

void __wrap_clearerr()
{
    return;
}

char * __wrap_fgets(char *__restrict __s, int __n, FILE *__restrict __stream)
{
    check_expected(__n);
    check_expected_ptr(__stream);

    strcpy(__s, mock_type(char *));

    return mock_type(char *);
}

void test_jqueue_init(void **state)
{
    (void) state;

    file_queue *fileq;

    os_calloc(1, sizeof(file_queue), fileq);

    jqueue_init(fileq);

    assert_int_equal(fileq->last_change, 0);
    assert_int_equal(fileq->year, 0);
    assert_int_equal(fileq->day, 0);
    assert_int_equal(fileq->flags, 0);
    assert_null(fileq->mon[0]);
    assert_null(fileq->file_name[0]);
    assert_null(fileq->fp);

    free(fileq);
}

void test_jqueue_open_fail_fopen(void **state)
{
    (void) state;

    file_queue *fileq;

    os_calloc(1, sizeof(file_queue), fileq);

    /* fopen fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");

    int ret = jqueue_open(fileq, 0);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);

    free(fileq);
}

void test_jqueue_open_fail_fseek(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* fseek fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, -1);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = jqueue_open(fileq, -1);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);

    free(fp);
    free(fileq);
}

void test_jqueue_open_fail_fstat(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* fstat fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, -1);
    expect_string(__wrap__merror, formatted_msg, "(1117): Could not retrieve informations of file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = jqueue_open(fileq, -1);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);

    free(fp);
    free(fileq);
}

void test_jqueue_open_success(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* success */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    int ret = jqueue_open(fileq, -1);

    assert_int_equal(ret, 0);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    free(fp);
    free(fileq);
}

void test_jqueue_next_fail(void **state)
{
    (void) state;

    file_queue *fileq;
    cJSON *json;

    os_calloc(1, sizeof(file_queue), fileq);

    /* jqueue_open fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");

    json = jqueue_next(fileq);

    assert_null(json);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);

    free(fileq);
}

void test_jqueue_next_success_newline(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    cJSON *json;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* fgets success with \n */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    json = jqueue_next(fileq);

    assert_string_equal(cJSON_GetObjectItem(json, "Test")->valuestring, "Hello World 1");
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    cJSON_Delete(json);

    free(fp);
    free(fileq);
}

void test_jqueue_next_success_no_newline(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    cJSON *json;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* fgets success without \n */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 2\"}");
    will_return(__wrap_fgets, "ok");

    json = jqueue_next(fileq);

    assert_string_equal(cJSON_GetObjectItem(json, "Test")->valuestring, "Hello World 2");
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    cJSON_Delete(json);

    free(fp);
    free(fileq);
}

void test_jqueue_close(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    int ret = jqueue_open(fileq, -1);

    assert_int_equal(ret, 0);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    jqueue_close(fileq);

    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);

    free(fp);
    free(fileq);
}

void test_jqueue_flags(void **state)
{
    (void) state;

    file_queue *fileq;

    os_calloc(1, sizeof(file_queue), fileq);

    jqueue_init(fileq);

    assert_int_equal(fileq->flags, 0);

    jqueue_flags(fileq, CRALERT_READ_ALL | CRALERT_FP_SET);

    assert_int_equal(fileq->flags, CRALERT_READ_ALL | CRALERT_FP_SET);

    free(fileq);
}

void test_handle_jqueue_fail_fopen(void **state)
{
    (void) state;

    file_queue *fileq;

    os_calloc(1, sizeof(file_queue), fileq);

    /* flag 0, fopen fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, NULL);

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, 0);
    assert_null(fileq->fp);

    free(fileq);
}

void test_handle_jqueue_fail_fseek(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* flag 0, fseek fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, -1);
    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file '' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, -1);
    assert_null(fileq->fp);

    free(fp);
    free(fileq);
}

void test_handle_jqueue_fail_fstat(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* flag 0, fstat fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, -1);
    expect_string(__wrap__merror, formatted_msg, "(1117): Could not retrieve informations of file '' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, -1);
    assert_null(fileq->fp);

    free(fp);
    free(fileq);
}

void test_handle_jqueue_success(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* flag 0, success */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, 1);
    assert_ptr_equal(fileq->fp, fp);

    free(fp);
    free(fileq);
}

void test_handle_jqueue_flag_fp_set(void **state)
{
    (void) state;

    file_queue *fileq;

    os_calloc(1, sizeof(file_queue), fileq);

    /* flag CRALERT_FP_SET, fail */

    jqueue_init(fileq);

    int ret = Handle_JQueue(fileq, CRALERT_FP_SET);

    assert_int_equal(ret, 0);
    assert_null(fileq->fp);

    free(fileq);
}

void test_handle_jqueue_flag_read_all(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* flag CRALERT_READ_ALL, success */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fstat, 1);

    int ret = Handle_JQueue(fileq, CRALERT_READ_ALL);

    assert_int_equal(ret, 1);
    assert_ptr_equal(fileq->fp, fp);

    free(fp);
    free(fileq);
}

void test_get_alert_json_data_fail(void **state)
{
    (void) state;

    file_queue *fileq;
    alert_data *alert;

    os_calloc(1, sizeof(file_queue), fileq);

    /* jqueue_next fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");

    alert = GetAlertJSONData(fileq);

    assert_null(alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);

    free(fileq);
}

void test_get_alert_json_data_no_rule(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* jqueue_next success, no rule */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\","
                               "\"full_log\":\"Test full log\"}\n");
    will_return(__wrap_fgets, "ok");

    alert = GetAlertJSONData(fileq);

    assert_null(alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    free(fp);
    free(fileq);
}

void test_get_alert_json_data_no_full_log(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* jqueue_next success, no full_log */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"rule\":{\"id\":\"1900\","
                                         "\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"],"
                                         "\"level\":10},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\"}\n");
    will_return(__wrap_fgets, "ok");

    alert = GetAlertJSONData(fileq);

    assert_non_null(alert);
    assert_string_equal(alert->date, "16/01/2020 12:46Z");
    assert_int_equal(alert->rule, 1900);
    assert_string_equal(alert->comment, "rule description");
    assert_string_equal(alert->group, "group1,group2");
    assert_int_equal(alert->level, 10);
    assert_string_equal(alert->filename, "/foo/bar");
    assert_string_equal(alert->user, "root");
    assert_string_equal(alert->srcip, "10.0.0.1");
    assert_string_equal(alert->location, "test");
    assert_string_equal(alert->log[0], "{\"timestamp\":\"16/01/2020 12:46Z\","
                                        "\"rule\":{\"id\":\"1900\","
                                                  "\"description\":\"rule description\","
                                                  "\"groups\":[\"group1\",\"group2\"],"
                                                  "\"level\":10},"
                                        "\"syscheck\":{\"path\":\"/foo/bar\","
                                                      "\"uname_after\":\"root\"},"
                                        "\"srcip\":\"10.0.0.1\","
                                        "\"location\":\"test\"}");
    assert_null(alert->log[1]);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    FreeAlertData(alert);

    free(fp);
    free(fileq);
}

void test_get_alert_json_data_all_data(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* jqueue_next success, all data */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"rule\":{\"id\":\"1900\","
                                         "\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"],"
                                         "\"level\":10},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\","
                               "\"full_log\":\"Test full log\"}\n");
    will_return(__wrap_fgets, "ok");

    alert = GetAlertJSONData(fileq);

    assert_non_null(alert);
    assert_string_equal(alert->date, "16/01/2020 12:46Z");
    assert_int_equal(alert->rule, 1900);
    assert_string_equal(alert->comment, "rule description");
    assert_string_equal(alert->group, "group1,group2");
    assert_int_equal(alert->level, 10);
    assert_string_equal(alert->filename, "/foo/bar");
    assert_string_equal(alert->user, "root");
    assert_string_equal(alert->srcip, "10.0.0.1");
    assert_string_equal(alert->location, "test");
    assert_string_equal(alert->log[0], "Test full log");
    assert_null(alert->log[1]);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);

    FreeAlertData(alert);

    free(fp);
    free(fileq);
}

void test_read_json_mon_fail(void **state)
{
    (void) state;

    file_queue *fileq;
    alert_data *alert;

    os_calloc(1, sizeof(file_queue), fileq);

    /* Handle_JQueue fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, NULL);

    alert = Read_JSON_Mon(fileq, 0, 0);

    assert_null(alert);
    assert_null(fileq->fp);

    free(fileq);
}

void test_read_json_mon_no_alert_fail(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* Handle_JQueue success, jqueue_next no alert, Handle_JQueue fail */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));
    will_return(__wrap_fopen, NULL);

    alert = Read_JSON_Mon(fileq, &tm_result, 0);

    assert_null(alert);
    assert_null(fileq->fp);

    free(fp);
    free(fileq);
}

void test_read_json_mon_no_alert_retry_timeout(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* Handle_JQueue success, jqueue_next no alert, Handle_JQueue success, jqueue_next no alert, timeout */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    alert = Read_JSON_Mon(fileq, &tm_result, 2);

    assert_null(alert);
    assert_ptr_equal(fileq->fp, fp);

    free(fp);
    free(fileq);
}

void test_read_json_mon_no_alert_retry_success(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* Handle_JQueue success, jqueue_next no alert, Handle_JQueue success, jqueue_next success */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"rule\":{\"id\":\"1900\","
                                         "\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"],"
                                         "\"level\":10},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\","
                               "\"full_log\":\"Test full log\"}\n");
    will_return(__wrap_fgets, "ok");

    alert = Read_JSON_Mon(fileq, &tm_result, 2);

    assert_non_null(alert);
    assert_string_equal(alert->date, "16/01/2020 12:46Z");
    assert_int_equal(alert->rule, 1900);
    assert_string_equal(alert->comment, "rule description");
    assert_string_equal(alert->group, "group1,group2");
    assert_int_equal(alert->level, 10);
    assert_string_equal(alert->filename, "/foo/bar");
    assert_string_equal(alert->user, "root");
    assert_string_equal(alert->srcip, "10.0.0.1");
    assert_string_equal(alert->location, "test");
    assert_string_equal(alert->log[0], "Test full log");
    assert_null(alert->log[1]);
    assert_ptr_equal(fileq->fp, fp);

    FreeAlertData(alert);

    free(fp);
    free(fileq);
}

void test_read_json_mon_success(void **state)
{
    (void) state;

    file_queue *fileq;
    FILE *fp;
    alert_data *alert;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    os_calloc(1, sizeof(file_queue), fileq);
    os_calloc(1, sizeof(FILE), fp);

    /* Handle_JQueue success, jqueue_next success */

    jqueue_init(fileq);

    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"rule\":{\"id\":\"1900\","
                                         "\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"],"
                                         "\"level\":10},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\","
                               "\"full_log\":\"Test full log\"}\n");
    will_return(__wrap_fgets, "ok");

    alert = Read_JSON_Mon(fileq, &tm_result, 2);

    assert_non_null(alert);
    assert_string_equal(alert->date, "16/01/2020 12:46Z");
    assert_int_equal(alert->rule, 1900);
    assert_string_equal(alert->comment, "rule description");
    assert_string_equal(alert->group, "group1,group2");
    assert_int_equal(alert->level, 10);
    assert_string_equal(alert->filename, "/foo/bar");
    assert_string_equal(alert->user, "root");
    assert_string_equal(alert->srcip, "10.0.0.1");
    assert_string_equal(alert->location, "test");
    assert_string_equal(alert->log[0], "Test full log");
    assert_null(alert->log[1]);
    assert_ptr_equal(fileq->fp, fp);

    FreeAlertData(alert);

    free(fp);
    free(fileq);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_jqueue_init),
        cmocka_unit_test(test_jqueue_open_fail_fopen),
        cmocka_unit_test(test_jqueue_open_fail_fseek),
        cmocka_unit_test(test_jqueue_open_fail_fstat),
        cmocka_unit_test(test_jqueue_open_success),
        cmocka_unit_test(test_jqueue_next_fail),
        cmocka_unit_test(test_jqueue_next_success_newline),
        cmocka_unit_test(test_jqueue_next_success_no_newline),
        cmocka_unit_test(test_jqueue_close),
        cmocka_unit_test(test_jqueue_flags),
        cmocka_unit_test(test_handle_jqueue_fail_fopen),
        cmocka_unit_test(test_handle_jqueue_fail_fseek),
        cmocka_unit_test(test_handle_jqueue_fail_fstat),
        cmocka_unit_test(test_handle_jqueue_success),
        cmocka_unit_test(test_handle_jqueue_flag_fp_set),
        cmocka_unit_test(test_handle_jqueue_flag_read_all),
        cmocka_unit_test(test_get_alert_json_data_fail),
        cmocka_unit_test(test_get_alert_json_data_no_rule),
        cmocka_unit_test(test_get_alert_json_data_no_full_log),
        cmocka_unit_test(test_get_alert_json_data_all_data),
        cmocka_unit_test(test_read_json_mon_fail),
        cmocka_unit_test(test_read_json_mon_no_alert_fail),
        cmocka_unit_test(test_read_json_mon_no_alert_retry_timeout),
        cmocka_unit_test(test_read_json_mon_no_alert_retry_success),
        cmocka_unit_test(test_read_json_mon_success)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

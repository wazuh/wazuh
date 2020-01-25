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

static int test_mode = 0;

struct aux_struct {
    file_queue *fileq;
    FILE *fp;
    cJSON *json;
    alert_data *alert;
};

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

extern FILE * __real_fopen(const char * __filename, const char * __modes);
FILE * __wrap_fopen(const char * __filename, const char * __modes)
{
    if (test_mode) {
        check_expected(__filename);
        check_expected(__modes);

        return mock_type(FILE *);
    } else {
        return __real_fopen(__filename, __modes);
    }
}

extern int __real_fclose (FILE *__stream);
int __wrap_fclose(FILE *__stream)
{
    if (test_mode) {
        check_expected_ptr(__stream);

        return 0;
    } else {
        return __real_fclose(__stream);
    }
}

extern int __real_fseek(FILE *__stream, long int __off, int __whence);
int __wrap_fseek(FILE *__stream, long int __off, int __whence)
{
    if (test_mode) {
        return mock();
    } else {
        return __real_fseek(__stream, __off, __whence);
    }
}

extern int __real_fstat (int __fd, struct stat *__buf);
int __wrap_fstat(int __fd, struct stat *__buf)
{
    if (test_mode) {
        return mock();
    } else {
        return __real_fstat(__fd, __buf);
    }
}

void __wrap_fileno()
{
    return;
}

void __wrap_clearerr()
{
    return;
}

char * __wrap_fgets(char * __s, int __n, FILE * __stream)
{
    check_expected(__n);
    check_expected_ptr(__stream);

    strcpy(__s, mock_type(char *));

    return mock_type(char *);
}

static int init_test_mode(void **state)
{
    (void) state;

    test_mode = 1;

    return 0;
}

static int end_test_mode(void **state)
{
    (void) state;

    test_mode = 0;

    return 0;
}

static int allocate_fileq(void **state)
{
    file_queue *fileq;

    fileq = calloc(1, sizeof(file_queue));

    *state = fileq;

    return 0;
}

static int free_fileq(void **state)
{
    file_queue *fileq = *state;

    free(fileq);

    return 0;
}

static int allocate_and_init_aux_struct(void **state)
{
    struct aux_struct *aux;

    aux = calloc(1, sizeof(struct aux_struct));

    file_queue *fileq;
    FILE *fp;

    fileq = calloc(1, sizeof(file_queue));
    fp = calloc(1, sizeof(FILE));

    jqueue_init(fileq);

    aux->fileq = fileq;
    aux->fp = fp;
    aux->json = NULL;
    aux->alert = NULL;

    *state = aux;

    return 0;
}

static int free_aux_struct(void **state)
{
    struct aux_struct *aux = *state;

    free(aux->fileq);
    free(aux->fp);
    if (aux->json) {
        cJSON_Delete(aux->json);
    }
    if (aux->alert) {
        FreeAlertData(aux->alert);
    }

    free(aux);

    return 0;
}

void test_jqueue_init(void **state)
{
    file_queue *fileq = *state;

    jqueue_init(fileq);

    assert_int_equal(fileq->last_change, 0);
    assert_int_equal(fileq->year, 0);
    assert_int_equal(fileq->day, 0);
    assert_int_equal(fileq->flags, 0);
    assert_null(fileq->mon[0]);
    assert_null(fileq->file_name[0]);
    assert_null(fileq->fp);
}

void test_jqueue_open_fail_fopen(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    /* fopen fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");

    int ret = jqueue_open(fileq, 0);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);
}

void test_jqueue_open_fail_fseek(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* fseek fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, -1);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = jqueue_open(fileq, 1);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);
}

void test_jqueue_open_fail_fstat(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* fstat fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, -1);
    expect_string(__wrap__merror, formatted_msg, "(1117): Could not retrieve informations of file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = jqueue_open(fileq, 1);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);
}

void test_jqueue_open_success(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* success */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    int ret = jqueue_open(fileq, 1);

    assert_int_equal(ret, 0);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_jqueue_next_fail(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    /* jqueue_open fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");

    aux->json = jqueue_next(fileq);

    assert_null(aux->json);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);
}

void test_jqueue_next_success_newline(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* fgets success with \n */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    aux->json = jqueue_next(fileq);

    assert_string_equal(cJSON_GetObjectItem(aux->json, "Test")->valuestring, "Hello World 1");
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_jqueue_next_success_no_newline(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* fgets success without \n */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 2\"}");
    will_return(__wrap_fgets, "ok");

    aux->json = jqueue_next(fileq);

    assert_string_equal(cJSON_GetObjectItem(aux->json, "Test")->valuestring, "Hello World 2");
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_jqueue_close(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    fileq->fp = aux->fp;

    expect_memory(__wrap_fclose, __stream, aux->fp, sizeof(aux->fp));

    jqueue_close(fileq);

    assert_string_equal(fileq->file_name, "");
    assert_null(fileq->fp);
}

void test_jqueue_flags(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    assert_int_equal(fileq->flags, 0);

    jqueue_flags(fileq, CRALERT_READ_ALL | CRALERT_FP_SET);

    assert_int_equal(fileq->flags, CRALERT_READ_ALL | CRALERT_FP_SET);
}

void test_handle_jqueue_fail_fopen(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    /* flag 0, fopen fail */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '' due to [(0)-(Success)].");

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, 0);
    assert_null(fileq->fp);
}

void test_handle_jqueue_fail_fseek(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* flag 0, fseek fail */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, -1);
    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file '' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, -1);
    assert_null(fileq->fp);
}

void test_handle_jqueue_fail_fstat(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* flag 0, fstat fail */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, -1);
    expect_string(__wrap__merror, formatted_msg, "(1117): Could not retrieve informations of file '' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, -1);
    assert_null(fileq->fp);
}

void test_handle_jqueue_success(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* flag 0, success */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    int ret = Handle_JQueue(fileq, 0);

    assert_int_equal(ret, 1);
    assert_ptr_equal(fileq->fp, fp);
}

void test_handle_jqueue_flag_fp_set(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    /* flag CRALERT_FP_SET, fail */

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '' due to [(0)-(Success)].");

    int ret = Handle_JQueue(fileq, CRALERT_FP_SET);

    assert_int_equal(ret, 0);
    assert_null(fileq->fp);
}

void test_handle_jqueue_flag_read_all(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* flag CRALERT_READ_ALL, success */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fstat, 1);

    int ret = Handle_JQueue(fileq, CRALERT_READ_ALL);

    assert_int_equal(ret, 1);
    assert_ptr_equal(fileq->fp, fp);
}

void test_handle_jqueue_flag_fp_set_read_all(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    fileq->fp = aux->fp;

    /* flag CRALERT_READ_ALL, success */

    will_return(__wrap_fstat, 1);

    int ret = Handle_JQueue(fileq, CRALERT_FP_SET | CRALERT_READ_ALL);

    assert_int_equal(ret, 1);
    assert_ptr_equal(fileq->fp, aux->fp);
}

void test_init_jsonqueue_read_all_fail(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* flag CRALERT_READ_ALL, fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fstat, -1);
    expect_string(__wrap__merror, formatted_msg, "(1117): Could not retrieve informations of file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));

    int ret = Init_JsonQueue(fileq, &tm_result, CRALERT_READ_ALL);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_int_equal(fileq->flags, CRALERT_READ_ALL);
    assert_null(fileq->fp);
}

void test_init_jsonqueue_read_all_success(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* flag CRALERT_READ_ALL, fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fstat, 1);

    int ret = Init_JsonQueue(fileq, &tm_result, CRALERT_READ_ALL);

    assert_int_equal(ret, 0);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_int_equal(fileq->flags, CRALERT_READ_ALL);
    assert_ptr_equal(fileq->fp, fp);
}

void test_init_jsonqueue_fp_set_read_all_fail(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    fileq->fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* flag CRALERT_READ_ALL, fail */

    will_return(__wrap_fstat, -1);
    expect_string(__wrap__merror, formatted_msg, "(1117): Could not retrieve informations of file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");
    expect_memory(__wrap_fclose, __stream, aux->fp, sizeof(aux->fp));

    int ret = Init_JsonQueue(fileq, &tm_result, CRALERT_FP_SET | CRALERT_READ_ALL);

    assert_int_equal(ret, -1);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_int_equal(fileq->flags, CRALERT_FP_SET | CRALERT_READ_ALL);
    assert_null(fileq->fp);
}

void test_init_jsonqueue_fp_set_read_all_success(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    fileq->fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* flag CRALERT_READ_ALL, fail */

    will_return(__wrap_fstat, 1);

    int ret = Init_JsonQueue(fileq, &tm_result, CRALERT_FP_SET | CRALERT_READ_ALL);

    assert_int_equal(ret, 0);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_int_equal(fileq->flags, CRALERT_FP_SET | CRALERT_READ_ALL);
    assert_ptr_equal(fileq->fp, aux->fp);
}

void test_get_alert_json_data_fail(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    /* jqueue_next fail */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/logs/alerts/alerts.json' due to [(0)-(Success)].");

    aux->alert = GetAlertJSONData(fileq);

    assert_null(aux->alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_null(fileq->fp);
}

void test_get_alert_json_data_no_timestamp(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* jqueue_next success, no rule */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"rule\":{\"id\":\"1900\","
                                         "\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"],"
                                         "\"level\":10},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'timestamp' field in 'alert' json.");

    aux->alert = GetAlertJSONData(fileq);

    assert_null(aux->alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_get_alert_json_data_no_rule(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* jqueue_next success, no rule */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
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

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'rule' field in 'alert' json.");

    aux->alert = GetAlertJSONData(fileq);

    assert_null(aux->alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_get_alert_json_data_no_rule_id(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* jqueue_next success, no rule */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"rule\":{\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"],"
                                         "\"level\":10},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'id' field in 'alert' json.");

    aux->alert = GetAlertJSONData(fileq);

    assert_null(aux->alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_get_alert_json_data_no_rule_level(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* jqueue_next success, no rule */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"timestamp\":\"16/01/2020 12:46Z\","
                               "\"rule\":{\"id\":\"1900\","
                                         "\"description\":\"rule description\","
                                         "\"groups\":[\"group1\",\"group2\"]},"
                               "\"syscheck\":{\"path\":\"/foo/bar\","
                                             "\"uname_after\":\"root\"},"
                               "\"srcip\":\"10.0.0.1\","
                               "\"location\":\"test\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'level' field in 'alert' json.");

    aux->alert = GetAlertJSONData(fileq);

    assert_null(aux->alert);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_get_alert_json_data_no_full_log(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* jqueue_next success, no full_log */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
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

    aux->alert = GetAlertJSONData(fileq);

    assert_non_null(aux->alert);
    assert_string_equal(aux->alert->date, "16/01/2020 12:46Z");
    assert_int_equal(aux->alert->rule, 1900);
    assert_string_equal(aux->alert->comment, "rule description");
    assert_string_equal(aux->alert->group, "group1,group2");
    assert_int_equal(aux->alert->level, 10);
    assert_string_equal(aux->alert->filename, "/foo/bar");
    assert_string_equal(aux->alert->user, "root");
    assert_string_equal(aux->alert->srcip, "10.0.0.1");
    assert_string_equal(aux->alert->location, "test");
    assert_string_equal(aux->alert->log[0], "{\"timestamp\":\"16/01/2020 12:46Z\","
                                             "\"rule\":{\"id\":\"1900\","
                                                       "\"description\":\"rule description\","
                                                       "\"groups\":[\"group1\",\"group2\"],"
                                                       "\"level\":10},"
                                             "\"syscheck\":{\"path\":\"/foo/bar\","
                                                           "\"uname_after\":\"root\"},"
                                             "\"srcip\":\"10.0.0.1\","
                                             "\"location\":\"test\"}");
    assert_null(aux->alert->log[1]);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_get_alert_json_data_all_data(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    /* jqueue_next success, all data */

    expect_string(__wrap_fopen, __filename, "/var/ossec/logs/alerts/alerts.json");
    expect_string(__wrap_fopen, __modes, "r");
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

    aux->alert = GetAlertJSONData(fileq);

    assert_non_null(aux->alert);
    assert_string_equal(aux->alert->date, "16/01/2020 12:46Z");
    assert_int_equal(aux->alert->rule, 1900);
    assert_string_equal(aux->alert->comment, "rule description");
    assert_string_equal(aux->alert->group, "group1,group2");
    assert_int_equal(aux->alert->level, 10);
    assert_string_equal(aux->alert->filename, "/foo/bar");
    assert_string_equal(aux->alert->user, "root");
    assert_string_equal(aux->alert->srcip, "10.0.0.1");
    assert_string_equal(aux->alert->location, "test");
    assert_string_equal(aux->alert->log[0], "Test full log");
    assert_null(aux->alert->log[1]);
    assert_string_equal(fileq->file_name, "/var/ossec/logs/alerts/alerts.json");
    assert_ptr_equal(fileq->fp, fp);
}

void test_read_json_mon_fail(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;

    /* Handle_JQueue fail */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '' due to [(0)-(Success)].");

    aux->alert = Read_JSON_Mon(fileq, 0, 0);

    assert_null(aux->alert);
    assert_null(fileq->fp);
}

void test_read_json_mon_no_alert_fail(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* Handle_JQueue success, jqueue_next no alert, Handle_JQueue fail */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'timestamp' field in 'alert' json.");

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));
    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '' due to [(0)-(Success)].");

    aux->alert = Read_JSON_Mon(fileq, &tm_result, 0);

    assert_null(aux->alert);
    assert_null(fileq->fp);
}

void test_read_json_mon_no_alert_retry_timeout(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* Handle_JQueue success, jqueue_next no alert, Handle_JQueue success, jqueue_next no alert, timeout */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'timestamp' field in 'alert' json.");

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));
    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'timestamp' field in 'alert' json.");

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'timestamp' field in 'alert' json.");

    aux->alert = Read_JSON_Mon(fileq, &tm_result, 2);

    assert_null(aux->alert);
    assert_ptr_equal(fileq->fp, fp);
}

void test_read_json_mon_no_alert_retry_success(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* Handle_JQueue success, jqueue_next no alert, Handle_JQueue success, jqueue_next success */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fseek, 1);
    will_return(__wrap_fstat, 1);

    expect_value(__wrap_fgets, __n, OS_MAXSTR + 1);
    expect_memory(__wrap_fgets, __stream, fp, sizeof(fp));
    will_return(__wrap_fgets, "{\"Test\":\"Hello World 1\"}\n");
    will_return(__wrap_fgets, "ok");

    expect_string(__wrap__merror, formatted_msg, "(1263): Couldn't find 'timestamp' field in 'alert' json.");

    expect_memory(__wrap_fclose, __stream, fp, sizeof(fp));
    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
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

    aux->alert = Read_JSON_Mon(fileq, &tm_result, 2);

    assert_non_null(aux->alert);
    assert_string_equal(aux->alert->date, "16/01/2020 12:46Z");
    assert_int_equal(aux->alert->rule, 1900);
    assert_string_equal(aux->alert->comment, "rule description");
    assert_string_equal(aux->alert->group, "group1,group2");
    assert_int_equal(aux->alert->level, 10);
    assert_string_equal(aux->alert->filename, "/foo/bar");
    assert_string_equal(aux->alert->user, "root");
    assert_string_equal(aux->alert->srcip, "10.0.0.1");
    assert_string_equal(aux->alert->location, "test");
    assert_string_equal(aux->alert->log[0], "Test full log");
    assert_null(aux->alert->log[1]);
    assert_ptr_equal(fileq->fp, fp);
}

void test_read_json_mon_success(void **state)
{
    struct aux_struct *aux = *state;

    file_queue *fileq = aux->fileq;
    FILE *fp = aux->fp;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* Handle_JQueue success, jqueue_next success */

    expect_string(__wrap_fopen, __filename, "");
    expect_string(__wrap_fopen, __modes, "r");
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

    aux->alert = Read_JSON_Mon(fileq, &tm_result, 2);

    assert_non_null(aux->alert);
    assert_string_equal(aux->alert->date, "16/01/2020 12:46Z");
    assert_int_equal(aux->alert->rule, 1900);
    assert_string_equal(aux->alert->comment, "rule description");
    assert_string_equal(aux->alert->group, "group1,group2");
    assert_int_equal(aux->alert->level, 10);
    assert_string_equal(aux->alert->filename, "/foo/bar");
    assert_string_equal(aux->alert->user, "root");
    assert_string_equal(aux->alert->srcip, "10.0.0.1");
    assert_string_equal(aux->alert->location, "test");
    assert_string_equal(aux->alert->log[0], "Test full log");
    assert_null(aux->alert->log[1]);
    assert_ptr_equal(fileq->fp, fp);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_jqueue_init, allocate_fileq, free_fileq),
        cmocka_unit_test_setup_teardown(test_jqueue_open_fail_fopen, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_open_fail_fseek, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_open_fail_fstat, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_open_success, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_next_fail, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_next_success_newline, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_next_success_no_newline, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_close, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_jqueue_flags, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_fail_fopen, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_fail_fseek, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_fail_fstat, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_success, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_flag_fp_set, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_flag_read_all, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_handle_jqueue_flag_fp_set_read_all, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_init_jsonqueue_read_all_fail, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_init_jsonqueue_read_all_success, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_init_jsonqueue_fp_set_read_all_fail, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_init_jsonqueue_fp_set_read_all_success, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_fail, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_no_timestamp, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_no_rule, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_no_rule_id, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_no_rule_level, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_no_full_log, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_get_alert_json_data_all_data, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_read_json_mon_fail, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_read_json_mon_no_alert_fail, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_read_json_mon_no_alert_retry_timeout, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_read_json_mon_no_alert_retry_success, allocate_and_init_aux_struct, free_aux_struct),
        cmocka_unit_test_setup_teardown(test_read_json_mon_success, allocate_and_init_aux_struct, free_aux_struct)
    };
    return cmocka_run_group_tests(tests, init_test_mode, end_test_mode);
}

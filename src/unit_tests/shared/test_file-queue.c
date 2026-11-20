/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../headers/shared.h"
#include "../../headers/file-queue.h"

static const char two_alerts[] =
    "** Alert 1793500000.1: - syslog,sshd,\n"
    "2026 Nov 06 11:40:01 (agent) any->/var/log/auth.log\n"
    "Rule: 5760 (level 5) -> 'sshd: authentication failed.'\n"
    "first log line\n"
    "\n"
    "** Alert 1793500000.2: - syslog,\n"
    "2026 Nov 06 11:40:02 (agent) any->/var/log/auth.log\n"
    "Rule: 5715 (level 3) -> 'sshd: authentication success.'\n"
    "second log line\n"
    "\n";

/* The input must fit in the pipe buffer, since nothing reads while writing */
static FILE *open_pipe_with(const char *input) {
    int fds[2];
    assert_int_equal(pipe(fds), 0);
    assert_int_equal(write(fds[1], input, strlen(input)), (ssize_t)strlen(input));
    close(fds[1]);

    FILE *fp = fdopen(fds[0], "r");
    assert_non_null(fp);
    return fp;
}

static FILE *open_tmpfile_with(const char *input) {
    FILE *fp = tmpfile();
    assert_non_null(fp);
    assert_int_equal(fwrite(input, sizeof(char), strlen(input), fp), strlen(input));
    rewind(fp);
    return fp;
}

static int teardown_fileq(void **state) {
    file_queue *fileq = *state;

    if (fileq) {
        if (fileq->fp) {
            fclose(fileq->fp);
        }
        os_free(fileq->pending_line);
        free(fileq);
    }

    return 0;
}

/* Reads both alerts through Read_FileMon the way wazuh-reportd sets up its queue */
static void read_two_alerts(void **state, FILE *fp) {
    file_queue *fileq;
    struct tm tm;
    time_t now = time(NULL);

    localtime_r(&now, &tm);
    os_calloc(1, sizeof(file_queue), fileq);
    *state = fileq;
    fileq->fp = fp;

    assert_int_equal(Init_FileQueue(fileq, &tm, CRALERT_READ_ALL | CRALERT_FP_SET), 0);
    assert_null(fileq->pending_line);

    alert_data *al_data = Read_FileMon(fileq, &tm, 1);
    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.1");
    assert_int_equal(al_data->rule, 5760);
    assert_string_equal(al_data->log[0], "first log line");
    assert_string_equal(fileq->pending_line, "** Alert 1793500000.2: - syslog,\n");
    FreeAlertData(al_data);

    al_data = Read_FileMon(fileq, &tm, 1);
    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.2");
    assert_int_equal(al_data->rule, 5715);
    assert_string_equal(al_data->log[0], "second log line");
    FreeAlertData(al_data);

    /* A third read would hit end of input, which sleeps FQ_TIMEOUT before returning */
    assert_null(fileq->pending_line);
}

static void test_read_filemon_fp_set_pipe_returns_every_alert(void **state) {
    read_two_alerts(state, open_pipe_with(two_alerts));
}

static void test_read_filemon_fp_set_seekable_unchanged(void **state) {
    read_two_alerts(state, open_tmpfile_with(two_alerts));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_read_filemon_fp_set_pipe_returns_every_alert, teardown_fileq),
        cmocka_unit_test_teardown(test_read_filemon_fp_set_seekable_unchanged, teardown_fileq),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

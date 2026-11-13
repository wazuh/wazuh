/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to modulesd's C side of the indexer client runtime bridge
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <limits.h>
#include <cJSON.h>
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../../wazuh_modules/src/wm_indexer_runtime.h"
#include "../../../wazuh_modules/indexer_runtime/include/wm_indexer_runtime_api.h"
#include "../../../shared/include/defs.h"
#include "../../../shared/include/error_messages/error_messages.h"

/* wfopen() */
static int wfopen_calls = 0;
static char wfopen_path[PATH_MAX];
static int wfopen_errno = ENOENT;
static const char *wfopen_real_path = NULL;   /* set => wfopen() opens this file for real */

/* so_get_module_handle() / so_get_function_sym() */
static int get_handle_calls = 0;
static bool handle_available = true;
static int get_sym_calls = 0;
static const char *missing_symbol = NULL;   /* so_get_function_sym() returns NULL for it */
static int free_library_calls = 0;

/* The fake libwm_indexer_runtime.so */
static int fake_configure_calls = 0;
static char fake_text[16384];
static char fake_json[256];
static int fake_has_consumer = -1;
static int fake_configure_rc = 0;
static const char *fake_configure_reason = "";

static int fake_configure(const char *options_text, const char *indexer_json, int has_consumer, char *reason,
                          size_t reason_len) {
    fake_configure_calls++;
    snprintf(fake_text, sizeof(fake_text), "%s", options_text ? options_text : "(null)");
    snprintf(fake_json, sizeof(fake_json), "%s", indexer_json ? indexer_json : "(null)");
    fake_has_consumer = has_consumer;
    if (fake_configure_rc != 0 && reason && reason_len > 0) {
        snprintf(reason, reason_len, "%s", fake_configure_reason);
    }
    return fake_configure_rc;
}

static int fake_start_rc = 0;
static const char *fake_start_reason = "";

static int fake_start(wmir_log_fn log, char *reason, size_t reason_len) {
    (void)log;
    if (fake_start_rc != 0 && reason && reason_len > 0) {
        snprintf(reason, reason_len, "%s", fake_start_reason);
    }
    return fake_start_rc;
}

static const void *fake_ref(void) {
    return NULL;
}

static void fake_begin_shutdown(long remaining_ms) {
    (void)remaining_ms;
}

static void fake_shutdown(void) {
}

FILE *__wrap_wfopen(const char *pathname, const char *mode) {
    (void)mode;
    wfopen_calls++;
    snprintf(wfopen_path, sizeof(wfopen_path), "%s", pathname);
    if (wfopen_real_path) {
        return fopen(wfopen_real_path, mode);
    }
    errno = wfopen_errno;
    return NULL;
}

int __wrap_so_free_library(void *handle) {
    (void)handle;
    free_library_calls++;
    return 0;
}

void *__wrap_so_get_module_handle(const char *so) {
    get_handle_calls++;
    assert_string_equal(so, "wm_indexer_runtime");
    return handle_available ? (void *)&fake_configure_calls : NULL;
}

void *__wrap_so_get_function_sym(void *handle, const char *function_name) {
    (void)handle;
    get_sym_calls++;
    if (missing_symbol && strcmp(function_name, missing_symbol) == 0) {
        return NULL;
    }
    if (strcmp(function_name, "wmir_configure") == 0) {
        return (void *)fake_configure;
    }
    if (strcmp(function_name, "wmir_start") == 0) {
        return (void *)fake_start;
    }
    if (strcmp(function_name, "wmir_ref") == 0) {
        return (void *)fake_ref;
    }
    if (strcmp(function_name, "wmir_begin_shutdown") == 0) {
        return (void *)fake_begin_shutdown;
    }
    if (strcmp(function_name, "wmir_shutdown") == 0) {
        return (void *)fake_shutdown;
    }
    fail_msg("unexpected symbol '%s'", function_name);
    return NULL;
}

/* cmocka check: the logged message contains the expected text. */
static int message_contains(const LargestIntegralType value, const LargestIntegralType check_value_data) {
    return strstr((const char *)value, (const char *)check_value_data) != NULL;
}

static int setup_test(void **state) {
    (void)state;
    wfopen_calls = 0;
    wfopen_path[0] = '\0';
    wfopen_errno = ENOENT;
    wfopen_real_path = NULL;
    get_handle_calls = 0;
    handle_available = true;
    get_sym_calls = 0;
    missing_symbol = NULL;
    free_library_calls = 0;
    fake_configure_calls = 0;
    fake_text[0] = fake_json[0] = '\0';
    fake_has_consumer = -1;
    fake_configure_rc = 0;
    fake_configure_reason = "";
    fake_start_rc = 0;
    fake_start_reason = "";
    return 0;
}

// Without a consumer nothing is loaded and nothing is read.
static void configure_no_consumer_loads_nothing(void **state) {
    (void)state;

    assert_int_equal(wm_indexer_runtime_configure(NULL, false), 0);

    assert_int_equal(get_handle_calls, 0);
    assert_int_equal(get_sym_calls, 0);
    assert_int_equal(fake_configure_calls, 0);
}

// The library is required once a module consumes the runtime: absent => an error naming it, and -1.
static void configure_missing_library(void **state) {
    (void)state;
    handle_available = false;

    expect_any(__wrap__mterror, tag);
    expect_check(__wrap__mterror, formatted_msg, message_contains, "wm_indexer_runtime");

    assert_int_equal(wm_indexer_runtime_configure(NULL, true), -1);

    assert_int_equal(get_handle_calls, 1);
    assert_int_equal(fake_configure_calls, 0);
}

// A library without one of the five symbols is a broken installation: an error naming the symbol, and -1.
static void configure_missing_symbol(void **state) {
    (void)state;
    missing_symbol = "wmir_begin_shutdown";

    expect_any(__wrap__mterror, tag);
    expect_check(__wrap__mterror, formatted_msg, message_contains, "wmir_begin_shutdown");

    assert_int_equal(wm_indexer_runtime_configure(NULL, true), -1);

    assert_int_equal(free_library_calls, 1);
    assert_int_equal(fake_configure_calls, 0);
    assert_null(wm_indexer_runtime_ref());
}

// An absent internal-options file is the defaults: empty text, no log.
static void configure_missing_file_silent(void **state) {
    (void)state;
    wfopen_errno = ENOENT;

    assert_int_equal(wm_indexer_runtime_configure(NULL, true), 0);

    assert_int_equal(wfopen_calls, 1);
    assert_string_equal(wfopen_path, WAZUH_LDEFINES);
    assert_int_equal(fake_configure_calls, 1);
    assert_string_equal(fake_text, "");
    assert_string_equal(fake_json, "{}");
    assert_int_equal(fake_has_consumer, 1);
}

// Present but unreadable: one error naming the path, then the defaults.
static void configure_unreadable_logs_path(void **state) {
    (void)state;
    wfopen_errno = EACCES;

    expect_any(__wrap__mterror, tag);
    expect_check(__wrap__mterror, formatted_msg, message_contains, WAZUH_LDEFINES);

    assert_int_equal(wm_indexer_runtime_configure(NULL, true), 0);

    assert_int_equal(fake_configure_calls, 1);
    assert_string_equal(fake_text, "");
    assert_string_equal(fake_json, "{}");
}

// The library's refusal comes back verbatim in the log and as -1.
static void configure_invalid_reports_reason(void **state) {
    (void)state;
    wfopen_errno = ENOENT;
    fake_configure_rc = -1;
    fake_configure_reason = "InvalidConfig: wazuh_modules.indexer_client_x";

    expect_any(__wrap__mterror, tag);
    expect_check(__wrap__mterror, formatted_msg, message_contains, "InvalidConfig: wazuh_modules.indexer_client_x");

    assert_int_equal(wm_indexer_runtime_configure(NULL, true), -1);

    assert_int_equal(fake_configure_calls, 1);
}

// The whole file reaches the library, however long (here > 4096 bytes, the first read buffer), with the
// indexer_client key last.
static void configure_reads_whole_file(void **state) {
    (void)state;
    char path[] = "/tmp/test_wm_indexer_runtime_XXXXXX";
    int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);

    static char expected[12288];
    size_t len = 0;
    for (int i = 0; len < 9000; i++) {
        len += (size_t)snprintf(expected + len, sizeof(expected) - len, "analysisd.filler_%04d=%d\n", i, i);
    }
    len += (size_t)snprintf(expected + len, sizeof(expected) - len, "wazuh_modules.indexer_client_x=1\n");
    assert_int_equal(fwrite(expected, 1, len, fp), len);
    fclose(fp);
    wfopen_real_path = path;

    int rc = wm_indexer_runtime_configure(NULL, true);
    unlink(path);

    assert_int_equal(rc, 0);
    assert_int_equal(fake_configure_calls, 1);
    assert_int_equal(strlen(fake_text), len);
    assert_string_equal(fake_text, expected);
}

// A runtime that does not start is one error carrying the library's reason, and -1 (modulesd goes on).
static void start_failure_logs_reason(void **state) {
    (void)state;
    fake_start_rc = -1;
    fake_start_reason = "InvalidConfig: indexer credentials: empty user";

    expect_any(__wrap__mterror, tag);
    expect_check(__wrap__mterror, formatted_msg, message_contains, "InvalidConfig: indexer credentials: empty user");

    assert_int_equal(wm_indexer_runtime_start(), -1);
}

int main(void) {
    // Order matters: the library handle is cached once loaded, so the cases that need it absent run first.
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(configure_no_consumer_loads_nothing, setup_test),
        cmocka_unit_test_setup(configure_missing_library, setup_test),
        cmocka_unit_test_setup(configure_missing_symbol, setup_test),
        cmocka_unit_test_setup(configure_missing_file_silent, setup_test),
        cmocka_unit_test_setup(configure_unreadable_logs_path, setup_test),
        cmocka_unit_test_setup(configure_invalid_reports_reason, setup_test),
        cmocka_unit_test_setup(configure_reads_whole_file, setup_test),
        cmocka_unit_test_setup(start_failure_logs_reason, setup_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

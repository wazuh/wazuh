/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "exec_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>


extern void write_date_storage();

int __wrap_wpclose(__attribute__((unused)) wfd_t * wfd) {
    return mock();
}

wfd_t *__wrap_wpopenl(__attribute__((unused)) const char * path, __attribute__((unused)) int flags, ...) {
    return mock_type(wfd_t *);
}

// Passive record of the most recent wpopenv() call's argv, for tests that
// need to assert on exact command-line contents (flag placement,
// add-vs-delete, address-family-specific arguments). Purely observational:
// it doesn't use cmocka's expect_*/check_expected mechanism, so it can't
// break any existing caller of this wrapper that only sets will_return().
#define WPOPENV_ARGV_CAPTURE_MAX 16
#define WPOPENV_ARGV_CAPTURE_LEN 256

static char wpopenv_argv_capture[WPOPENV_ARGV_CAPTURE_MAX][WPOPENV_ARGV_CAPTURE_LEN];
static int wpopenv_argv_capture_count = 0;

int wpopenv_captured_argc(void) {
    return wpopenv_argv_capture_count;
}

const char *wpopenv_captured_argv(int index) {
    if (index < 0 || index >= wpopenv_argv_capture_count) {
        return NULL;
    }
    return wpopenv_argv_capture[index];
}

wfd_t *__wrap_wpopenv(__attribute__((unused)) const char * path,
                      char * const * argv,
                      __attribute__((unused)) int flags) {
    wpopenv_argv_capture_count = 0;
    if (argv) {
        while (argv[wpopenv_argv_capture_count] != NULL && wpopenv_argv_capture_count < WPOPENV_ARGV_CAPTURE_MAX) {
            strncpy(wpopenv_argv_capture[wpopenv_argv_capture_count], argv[wpopenv_argv_capture_count], WPOPENV_ARGV_CAPTURE_LEN - 1);
            wpopenv_argv_capture[wpopenv_argv_capture_count][WPOPENV_ARGV_CAPTURE_LEN - 1] = '\0';
            wpopenv_argv_capture_count++;
        }
    }
    return mock_type(wfd_t *);
}

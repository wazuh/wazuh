/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "run_realtime_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_realtime_adddir(const char *dir,
                           __attribute__((unused)) directory_t *configuration) {
    check_expected(dir);

    return mock();
}


int __wrap_realtime_start() {
    return 0;
}
void __wrap_realtime_process() {
    function_called();
}

void expect_realtime_adddir_call(const char *path, int ret) {
    expect_string(__wrap_realtime_adddir, dir, path);
    will_return(__wrap_realtime_adddir, ret);
}

int __wrap_fim_add_inotify_watch(const char *dir,
                                 __attribute__((unused)) const directory_t *configuration) {
    check_expected(dir);

    return mock();
}

void __wrap_realtime_sanitize_watch_map() {
    function_called();
}

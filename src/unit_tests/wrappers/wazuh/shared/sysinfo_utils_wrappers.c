/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sysinfo_utils_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include "../../common.h"

bool __wrap_w_sysinfo_init(__attribute__((__unused__)) w_sysinfo_helpers_t * sysinfo) {
    if (test_mode) {
        bool ret = mock_type(bool);
        return ret;
    }
    return w_sysinfo_init(sysinfo);
}

bool __wrap_w_sysinfo_deinit(__attribute__((__unused__)) w_sysinfo_helpers_t * sysinfo) {
    if (test_mode) {
        bool ret = mock_type(bool);
        return ret;
    }
    return w_sysinfo_deinit(sysinfo);
}

cJSON * __wrap_w_sysinfo_get_processes(__attribute__((__unused__)) w_sysinfo_helpers_t * sysinfo) {
    if (test_mode) {
        cJSON * ret = mock_type(cJSON *);
        return ret;
    }
    return w_sysinfo_get_processes(sysinfo);
}

cJSON * __wrap_w_sysinfo_get_os(__attribute__((__unused__)) w_sysinfo_helpers_t * sysinfo) {
    if (test_mode) {
        cJSON * ret = mock_type(cJSON *);
        return ret;
    }
    return w_sysinfo_get_os(sysinfo);
}

pid_t * __wrap_w_get_process_childs(__attribute__((__unused__)) w_sysinfo_helpers_t * sysinfo,
                                    __attribute__((__unused__)) pid_t parent_pid,
                                    __attribute__((__unused__)) unsigned int max_count) {
    if (test_mode) {
        pid_t * ret = mock_type(pid_t *);
        return ret;
    }
    return w_get_process_childs(sysinfo, parent_pid, max_count);
}

char * __wrap_w_get_os_codename(__attribute__((__unused__)) w_sysinfo_helpers_t * sysinfo) {
    if (test_mode) {
        char * ret = mock_type(char *);
        return ret;
    }
    return w_get_os_codename(sysinfo);
}

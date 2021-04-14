/*
 * Wazuh module configuration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 6, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"
#define WIN32_MAX_FILES 200

int wm_logcollector_read(wm_logcollector_t *const logcollector) {
    int ret_val = OS_SUCCESS;

    if (NULL != logcollector) {
        logcollector->accept_remote = getDefine_Int(LOGCOLLECTOR_WM_NAME, "remote_commands", 0, 1);
        logcollector->loop_timeout = getDefine_Int(LOGCOLLECTOR_WM_NAME, "loop_timeout", 1, 120);
        logcollector->open_file_attempts = getDefine_Int(LOGCOLLECTOR_WM_NAME, "open_attempts", 0, 998);
        logcollector->vcheck_files = getDefine_Int(LOGCOLLECTOR_WM_NAME, "vcheck_files", 0, 1024);
        logcollector->maximum_lines = getDefine_Int(LOGCOLLECTOR_WM_NAME, "max_lines", 0, 1000000);
        logcollector->maximum_files = getDefine_Int(LOGCOLLECTOR_WM_NAME, "max_files", 1, 100000);
        logcollector->sock_fail_time = getDefine_Int(LOGCOLLECTOR_WM_NAME, "sock_fail_time", 1, 3600);
        logcollector->sample_log_length = getDefine_Int(LOGCOLLECTOR_WM_NAME, "sample_log_length", 1, 4096);
        logcollector->force_reload = getDefine_Int(LOGCOLLECTOR_WM_NAME, "force_reload", 0, 1);
        logcollector->reload_interval = getDefine_Int(LOGCOLLECTOR_WM_NAME, "reload_interval", 1, 86400);
        logcollector->reload_delay = getDefine_Int(LOGCOLLECTOR_WM_NAME, "reload_delay", 0, 30000);
        logcollector->free_excluded_files_interval = getDefine_Int(LOGCOLLECTOR_WM_NAME, "exclude_files_interval", 1, 172800);
        logcollector->state_interval = getDefine_Int(LOGCOLLECTOR_WM_NAME, "state_interval", 0, 3600);
        if (logcollector->force_reload && logcollector->reload_interval < logcollector->vcheck_files) {
            mwarn("Reload interval (%d) must be greater or equal than the checking interval (%d).", logcollector->reload_interval, logcollector->vcheck_files);
        }

#ifndef WIN32
        logcollector->nofile = getDefine_Int("logcollector", "rlimit_nofile", 1024, 1048576);
#endif

        if (logcollector->maximum_lines > 0 && logcollector->maximum_lines < 100) {
            merror("Definition 'logcollector.max_lines' must be 0 or 100..1000000.");
            ret_val = OS_INVALID;
        } else {
#ifndef WIN32
            if (logcollector->maximum_files > (int)logcollector->nofile - 100) {
                merror("Definition 'logcollector.max_files' must be lower than ('logcollector.rlimit_nofile' - 100).");
                ret_val = OS_SIZELIM;
            }
#else
            if (logcollector->maximum_files > WIN32_MAX_FILES) {
                /* Limit files on Windows as file descriptors are shared */
                logcollector->maximum_files = WIN32_MAX_FILES;
                mdebug1("The maximum number of files to monitor cannot exceed %d in Windows, so it will be limited.", WIN32_MAX_FILES);
            }
#endif
        }
    } else {
        ret_val = OS_UNDEF;
    }
    return ret_val;
}

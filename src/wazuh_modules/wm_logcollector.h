/*
 * Wazuh Module for Log Collector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * March 29, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules_def.h"
#include "os_xml/os_xml.h"

#ifndef WM_LOGCOLLECTOR
#define WM_LOGCOLLECTOR

extern const wm_context WM_LOGCOLLECTOR_CONTEXT;     // Context

typedef struct wm_logcollector_t {
    int accept_remote;
    int loop_timeout;
    int open_file_attempts;
    int vcheck_files;
    int maximum_lines;
    int maximum_files;
    int sock_fail_time;
    int sample_log_length;
    int force_reload;
    int reload_interval;
    int reload_delay;
    int free_excluded_files_interval;
    int state_interval;
#ifndef WIN32
    rlim_t nofile;
#endif
    logreader_config log_config;
} wm_logcollector_t;

// Parse Internal configuration
int wm_logcollector_read(wm_logcollector_t *wmlogcollector);

/* Frees the Logcollector config struct  */
void Free_Localfile(logreader_config * config);

/* Frees a localfile  */
void Free_Logreader(logreader * config);

/* Removes a specific localfile of an array */
int Remove_Localfile(logreader **logf, int i, int gl, int fr, logreader_glob *globf);

#endif //_WM_LOGCOLLECTOR

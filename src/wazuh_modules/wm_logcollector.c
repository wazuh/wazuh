/*
 * Wazuh LOGCOLLECTOR
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 11, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <stdlib.h>
#include "../../wmodules_def.h"
#include "wmodules.h"
#include "wm_logcollector.h"
#include "../logcollector/logcollector.h"
#include "defs.h"
#include "mq_op.h"

static void* wm_logcollector_main(wm_logcollector_t *data);         // Module main function. It won't return
static void wm_logcollector_destroy(wm_logcollector_t *data);       // Destroy data
cJSON *wm_logcollector_dump(const wm_logcollector_t *data);
extern int logr_queue;                                              // Output queue file descriptor

const wm_context WM_LOGCOLLECTOR_CONTEXT = {
    LOGCOLLECTOR_WM_NAME,
    (wm_routine)wm_logcollector_main,
    (wm_routine)(void *)wm_logcollector_destroy,
    (cJSON * (*)(const void *))wm_logcollector_dump,
    NULL,
};



static void wm_logcollector_log_config(wm_logcollector_t *data)
{
    cJSON * config_json = wm_logcollector_dump(data);
    if (config_json) {
        char * config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(WM_LOGCOLLECTOR_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

void* wm_logcollector_main(wm_logcollector_t *data) {

#ifndef WIN32
    // Set max open files limit
    struct rlimit rlimit = { data->nofile, data->nofile };

    if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
        merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)data->nofile, strerror(errno), errno);
    }
#endif

    mtinfo(WM_LOGCOLLECTOR_LOGTAG, "Starting Logcollector.");

    w_msg_hash_queues_init();

    accept_remote = data->accept_remote;
    loop_timeout = data->loop_timeout;
    open_file_attempts = data->open_file_attempts;
    vcheck_files = data->vcheck_files;
    maximum_lines = data->maximum_lines;
    maximum_files = data->maximum_files;
    sock_fail_time = data->sock_fail_time;
    sample_log_length = data->sample_log_length;
    force_reload = data->force_reload;
    reload_interval = data->reload_interval;
    reload_delay = data->reload_delay;
    free_excluded_files_interval = data->free_excluded_files_interval;
    state_interval = data->state_interval;

    logff = data->log_config.config;
    globs = data->log_config.globs;
    logsk = data->log_config.socket_list;

    wm_logcollector_log_config(data);

    /* Start the queue */
    if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQPATH);
    }

    LogCollectorStart();

    if (logr_queue) {
        close(logr_queue);
        logr_queue = 0;
    }
    mtinfo(WM_LOGCOLLECTOR_LOGTAG, "Module finished.");
    return 0;
}

void wm_logcollector_destroy(wm_logcollector_t *data) {
    os_free(data);
}

cJSON *wm_logcollector_dump(__attribute__((unused)) const wm_logcollector_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root,"LocalfileConfig",getLocalfileConfig());
    cJSON_AddItemToObject(root,"SocketConfig",getSocketConfig());
    cJSON_AddItemToObject(root,"LogcollectorInternalOptions",getLogcollectorInternalOptions());
    return root;
}

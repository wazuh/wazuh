/*
 * Wazuh Module - Configuration files checker
 * Copyright (C) 2015-2019, Wazuh Inc.
 * September, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#ifndef WM_CHECK_CONFIG_H
#define WM_CHECK_CONFIG_H

#define WM_CHECK_CONFIG_LOGTAG ARGV0 ":check_configuration"

#include "shared.h"
#include "wmodules.h"
#include "syscollector/syscollector.h"
#include "external/cJSON/cJSON.h"
#include "file_op.h"
#include "../os_net/os_net.h"
#include <ifaddrs.h>

extern const wm_context WM_CHK_CONF_CONTEXT;

typedef struct wm_check_conf_t {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
} wm_check_conf_t;

wmodule *wm_chk_conf_read();
int check_event_rcvd(const char *buffer, char **filetype, char **filepath);
int test_file(const char *filetype, const char *filepath, char **output);
void send_message(const char *output);


#endif
#endif

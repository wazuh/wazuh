/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 17, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __OPTIONS_H
#define __OPTIONS_H

/* Options attributes */
typedef struct _option_t {
    int def;
    int min;
    int max;
} option_t;

/* Syscheck options structure */
typedef struct _syscheck_option_t {
    option_t sleep;
    option_t sleep_after;
    option_t rt_delay;
    option_t max_fd_win_rt;
    option_t max_audit_entries;
    option_t default_max_depth;
    option_t symlink_scan_interval;
    option_t file_max_size;
    option_t logging;
} syscheck_option_t;

/* Rootcheck options structure */
typedef struct _rootcheck_option_t {
    option_t sleep;
} rootcheck_option_t;

/* Internal options structure */
typedef struct _option_set_t {
    syscheck_option_t syscheck;
    rootcheck_option_t rootcheck;
} option_set_t;

extern const option_set_t options;

#endif

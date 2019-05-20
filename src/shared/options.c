/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 17, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "options.h"

const option_set_t options = {
    .syscheck = {
        .sleep = {
            .def = 1,
            .min = 0,
            .max = 64
        },
        .sleep_after = {
            .def = 100,
            .min = 1,
            .max = 99999
        },
        .rt_delay = {
            .def = 10,
            .min = 1,
            .max = 1000
        },
        .max_fd_win_rt = {
            .def = 256,
            .min = 1,
            .max = 1024
        },
        .max_audit_entries = {
            .def = 256,
            .min = 1,
            .max = 4096
        },
        .default_max_depth = {
            .def = 256,
            .min = 1,
            .max = 320
        },
        .symlink_scan_interval = {
            .def = 600,
            .min = 1,
            .max = 2592000
        },
        .file_max_size = {
            .def = 1024,
            .min = 0,
            .max = 4095
        },
        .logging = {
            .def = 0,
            .min = 0,
            .max = 2
        }
    }
};

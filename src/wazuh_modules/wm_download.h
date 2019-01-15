/*
 * Wazuh Module for file downloads
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_DOWNLOAD_H
#define WM_DOWNLOAD_H

#define WM_DOWNLOAD_LOGTAG ARGV0 ":download"

typedef struct wm_download_t {
    unsigned int enabled:1;
} wm_download_t;

extern const wm_context WM_DOWNLOAD_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
wmodule * wm_download_read();

#endif // WM_DOWNLOAD_H

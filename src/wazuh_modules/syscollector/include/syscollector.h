/*
 * Wazuh Module for System inventory
 * Copyright (C) 2015-2020, Wazuh Inc.
 * March 9, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../wmodules_def.h"
#include "shared.h"
#include "version_op.h"

#ifndef WM_SYSCOLLECTOR
#define WM_SYSCOLLECTOR

//#ifdef __cplusplus
//extern "C" {
//#endif

extern const wm_context WM_SYS_CONTEXT;     // Context

#define WM_SYS_LOGTAG ARGV0 ":syscollector" // Tag for log messages

typedef struct wm_sys_flags_t {
    unsigned int enabled:1;                 // Main switch
    unsigned int scan_on_start:1;           // Scan always on start
    unsigned int hwinfo:1;                  // Hardware inventory
    unsigned int netinfo:1;                 // Network inventory
    unsigned int osinfo:1;                  // OS inventory
    unsigned int programinfo:1;             // Installed packages inventory
    unsigned int hotfixinfo:1;              // Windows hotfixes installed
    unsigned int portsinfo:1;               // Opened ports inventory
    unsigned int allports:1;                // Scan only listening ports or all
    unsigned int procinfo:1;                // Running processes inventory
} wm_sys_flags_t;

typedef struct wm_sys_state_t {
    time_t next_time;                       // Absolute time for next scan
} wm_sys_state_t;

typedef struct wm_sys_t {
    unsigned int interval;                  // Time interval between cycles (seconds)
    wm_sys_flags_t flags;                   // Flag bitfield
    wm_sys_state_t state;                   // Running state
} wm_sys_t;

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module);

/*#ifdef _cplusplus
}
#endif*/

#endif

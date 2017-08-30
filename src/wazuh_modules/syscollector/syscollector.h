/*
 * Wazuh Module for System inventory
 * Copyright (C) 2017 Wazuh Inc.
 * March 9, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../wmodules.h"

#ifndef WM_SYSCOLLECTOR
#define WM_SYSCOLLECTOR

#define TYPE_LENGTH 64
#define STATE_LENGTH 20
#define MTU_LENGTH 20
#define DHCP_LENGTH 10

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define WM_SYS_DEF_INTERVAL 3600            // Default cycle interval (1 hour)
#define WM_SYS_LOGTAG ARGV0 ":syscollector" // Tag for log messages
#define WM_SYS_IF_FILE "/etc/network/interfaces"
#define WM_SYS_IF_DIR_RH "/etc/sysconfig/network-scripts/"
#define WM_SYS_IF_DIR_SUSE "/etc/sysconfig/network/"
#define WM_SYS_DGW_FILE "/proc/net/route"
#define WM_SYS_IFDATA_DIR "/sys/class/net/"
#define WM_SYS_HW_DIR   "/sys/class/dmi/id"

typedef struct hw_info {
    char *cpu_name;
    int cpu_cores;
    double cpu_MHz;
    int ram_total;  // kB
    int ram_free;   // kB
} hw_info;

typedef struct wm_sys_flags_t {
    unsigned int enabled:1;                 // Main switch
    unsigned int scan_on_start:1;           // Scan always on start
    unsigned int hardware:1;                // Hardware inventory
    unsigned int network:1;                 // Network inventory
    unsigned int os_scan:1;                 // OS inventory
} wm_sys_flags_t;

typedef struct wm_sys_state_t {
    time_t next_time;                       // Absolute time for next scan
} wm_sys_state_t;

typedef struct wm_sys_t {
    unsigned int interval;                  // Time interval between cycles (seconds)
    wm_sys_flags_t flags;                   // Flag bitfield
    wm_sys_state_t state;                   // Running state
} wm_sys_t;

extern const wm_context WM_SYS_CONTEXT;     // Context

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module);

// Hardware inventory for Linux
void sys_hw_linux(int queue_fd, const char* LOCATION);

// Hardware inventory for Windows
void sys_hw_windows(const char* LOCATION);

// OS inventory for Linux
void sys_os_linux(int queue_fd, const char* LOCATION);

// OS inventory for Windows
void sys_os_windows(const char* LOCATION);

// Network inventory for Linux
void sys_network_linux(int queue_fd, const char* LOCATION);

// Network inventory for windows
void sys_network_windows(const char* LOCATION);

#endif

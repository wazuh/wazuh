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
#include "shared.h"

#ifndef WM_SYSCOLLECTOR
#define WM_SYSCOLLECTOR

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define PROTO_LENGTH 6
#define FORMAT_LENGTH 18
#define MAC_LENGTH 18
#define TYPE_LENGTH 64
#define STATE_LENGTH 20
#define MTU_LENGTH 20
#define DHCP_LENGTH 10
#define CLOCK_LENGTH 256

#define WM_SYS_DEF_INTERVAL 3600            // Default cycle interval (1 hour)
#define WM_SYS_LOGTAG ARGV0 ":syscollector" // Tag for log messages
#define WM_SYS_IF_FILE "/etc/network/interfaces"
#define WM_SYS_IF_DIR_RH "/etc/sysconfig/network-scripts/"
#define WM_SYS_IF_DIR_SUSE "/etc/sysconfig/network/"
#define WM_SYS_IFDATA_DIR "/sys/class/net/"
#define WM_SYS_HW_DIR   "/sys/class/dmi/id"
#define WM_SYS_NET_DIR  "/proc/net/"

#define SYSCOLLECTOR_PORTS_END      "{\"type\":\"port_end\"}"
#define SYSCOLLECTOR_PROGRAMS_END   "{\"type\":\"program_end\"}"
#define SYSCOLLECTOR_HARDWARE_END   "{\"type\":\"hardware_end\"}"
#define SYSCOLLECTOR_NETWORK_END    "{\"type\":\"network_end\"}"
#define SYSCOLLECTOR_PROCESSES_END  "{\"type\":\"process_end\"}"

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
    unsigned int hwinfo:1;                  // Hardware inventory
    unsigned int netinfo:1;                 // Network inventory
    unsigned int osinfo:1;                  // OS inventory
    unsigned int programinfo:1;             // Installed programs inventory
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

extern const wm_context WM_SYS_CONTEXT;     // Context

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module);

// Opened ports inventory for Linux
void sys_ports_linux(int queue_fd, const char* WM_SYS_LOCATION, int check_all);

// Opened ports inventory for Windows
void sys_ports_windows(const char* LOCATION, int check_all);

// Installed programs inventory for Linux
void sys_programs_linux(int queue_fd, const char* WM_SYS_LOCATION);

// Installed programs inventory for Windows
void sys_programs_windows(const char* LOCATION);

#if defined(__FreeBSD__)
// Installed programs inventory for BSD based systems
void sys_programs_bsd(int queue_fd, const char* LOCATION);
#endif

// Hardware inventory for Linux
void sys_hw_linux(int queue_fd, const char* LOCATION);

// Hardware inventory for BSD based systems
void sys_hw_bsd(int queue_fd, const char* LOCATION);

// Hardware inventory for Windows
void sys_hw_windows(const char* LOCATION);

// OS inventory for Unix
void sys_os_unix(int queue_fd, const char* LOCATION);

// OS inventory for Windows
void sys_os_windows(const char* LOCATION);

// Network inventory for BSD based systems
void sys_network_bsd(int queue_fd, const char* LOCATION);

// Network inventory for Linux
void sys_network_linux(int queue_fd, const char* LOCATION);

// Network inventory for windows
void sys_network_windows(const char* LOCATION);

// Running processes inventory
void sys_proc_linux(int queue_fd, const char* LOCATION);
void sys_proc_windows(const char* LOCATION);

#endif

/*
 * Wazuh Module for System inventory
 * Copyright (C) 2015-2019, Wazuh Inc.
 * March 9, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef ENABLE_SYSC

#include "../wmodules.h"
#include "shared.h"
#include "version_op.h"

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#include <netioapi.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winbase.h>
#endif

#ifndef WM_SYSCOLLECTOR
#define WM_SYSCOLLECTOR

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define ARCH32  0
#define ARCH64  1
#define NOARCH  2

#define LM_KEY   1
#define U_KEY    0

#define MAX_VALUE_NAME 16383

#define TOTALBYTES      8192
#define BYTEINCREMENT   4096

#define PROTO_LENGTH 6
#define MAC_LENGTH 18
#define TYPE_LENGTH 64
#define STATE_LENGTH 20
#define MTU_LENGTH 20
#define DHCP_LENGTH 10
#define V_LENGTH    128
#define COMMAND_LENGTH  512
#define PATH_LENGTH     512
#define TIME_LENGTH     64
#define ADDR6_LENGTH    256
#define IFNAME_LENGTH   256
#define SERIAL_LENGTH   512
#define KEY_LENGTH      255

#define TAG_NAME        1000
#define TAG_VERSION     1001
#define TAG_RELEASE     1002
#define TAG_EPOCH       1003
#define TAG_SUMMARY     1004
#define TAG_ITIME       1008
#define TAG_SIZE        1009
#define TAG_VENDOR      1011
#define TAG_GROUP       1016
#define TAG_SOURCE      1018
#define TAG_ARCH        1022

#define WM_SYS_DEF_INTERVAL 3600            // Default cycle interval (1 hour)
#define WM_SYS_LOGTAG ARGV0 ":syscollector" // Tag for log messages
#define WM_SYS_IF_FILE "/etc/network/interfaces"
#define WM_SYS_IF_DIR_RH "/etc/sysconfig/network-scripts/"
#define WM_SYS_IF_DIR_SUSE "/etc/sysconfig/network/"
#define WM_SYS_IFDATA_DIR "/sys/class/net/"
#define WM_SYS_HW_DIR   "/sys/class/dmi/id"
#define WM_SYS_NET_DIR  "/proc/net/"
#define RPM_DATABASE    "/var/lib/rpm/Packages"

/* MAC package search paths */

#define MAC_APPS        "/Applications"
#define UTILITIES       "/Applications/Utilities"
#define HOMEBREW_APPS   "/usr/local/Cellar"
#define INFO_FILE       "Contents/Info.plist"

typedef struct rpm_data {
    char *tag;
    int type;
    int offset;
    int count;
    struct rpm_data *next;
} rpm_data;

typedef struct hw_info {
    char *cpu_name;
    int cpu_cores;
    double cpu_MHz;
    uint64_t ram_total;  // kB
    uint64_t ram_free;   // kB
    int ram_usage;  // Percentage
} hw_info;

typedef struct wm_sys_flags_t {
    unsigned int enabled:1;                 // Main switch
    unsigned int scan_on_start:1;           // Scan always on start
    unsigned int hwinfo:1;                  // Hardware inventory
    unsigned int netinfo:1;                 // Network inventory
    unsigned int osinfo:1;                  // OS inventory
    unsigned int programinfo:1;             // Installed packages inventory
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

struct link_stats
{
    unsigned int rx_packets;    /* total packets received */
    unsigned int tx_packets;    /* total packets transmitted */
    unsigned int rx_bytes;      /* total bytes received */
    unsigned int tx_bytes;      /* total bytes transmitted */
    unsigned int rx_errors;     /* bad packets received */
    unsigned int tx_errors;     /* packet transmit problems */
    unsigned int rx_dropped;    /* no space in linux buffers */
    unsigned int tx_dropped;    /* no space available in linux */
};

extern const wm_context WM_SYS_CONTEXT;     // Context

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module);

// Opened ports inventory for Linux
void sys_ports_linux(int queue_fd, const char* WM_SYS_LOCATION, int check_all);

// Opened ports inventory for Windows
void sys_ports_windows(const char* LOCATION, int check_all);

// Installed packages inventory for Linux
void sys_packages_linux(int queue_fd, const char* WM_SYS_LOCATION);
char * sys_deb_packages(int queue_fd, const char* WM_SYS_LOCATION, int random_id);
char * sys_rpm_packages(int queue_fd, const char* WM_SYS_LOCATION, int random_id);

#ifdef WIN32
// Installed programs inventory for Windows
void sys_programs_windows(const char* LOCATION);

// Get values about a single program from the registry
void read_win_program(const char * sec_key, int arch, int root_key, int usec, const char * timestamp, int ID, const char * LOCATION);

// List installed programs from the registry
void list_programs(HKEY hKey, int arch, const char * root_key, int usec, const char * timestamp, int ID, const char * LOCATION);

// List Windows users from the registry
void list_users(HKEY hKey, int usec, const char * timestamp, int ID, const char * LOCATION);
#endif

#if defined(__FreeBSD__) || defined(__MACH__)
// Installed programs inventory for BSD based systems
void sys_packages_bsd(int queue_fd, const char* LOCATION);
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

// Read string from a byte array until find a NULL byte
char* read_string(u_int8_t* bytes);

// Read four bytes and retrieve its decimal value
int four_bytes_to_int32(u_int8_t* bytes);

// Read index entry from a RPM header
int read_entry(u_int8_t* bytes, rpm_data *info);

#endif
#endif

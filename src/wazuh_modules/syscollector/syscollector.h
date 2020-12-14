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
#define V_LENGTH    256
#define COMMAND_LENGTH  512
#define PATH_LENGTH     512
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
#define TAG_SOURCE      1044
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

#define WIN_REG_HOTFIX    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"
#define VISTA_REG_HOTFIX  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"
#define HOTFIX_INSTALLED  112
#define HOTFIX_SUPERSEDED 80
#define HOTFIX_STAGED     64

/* MAC package search paths */

#define MAC_APPS        "/Applications"
#define UTILITIES       "/Applications/Utilities"
#define HOMEBREW_APPS   "/usr/local/Cellar"
#define INFO_FILE       "Contents/Info.plist"

typedef enum sys_scan_event {
    HW_SCAN,
    OS_SCAN,
    IFACE_SCAN,
    PKG_SCAN,
    HFIX_SCAN,
    PORT_SCAN,
    PROC_SCAN
} sys_scan_event;

typedef enum sys_event_type {
    SYS_ADD,
    SYS_MODIFY,
    SYS_DELETE
} sys_event_type;

typedef struct hw_entry {
    char * board_serial;                    // Motherboard serial number
    char * cpu_name;                        // CPU name
    int cpu_cores;                          // Number of cores of the CPU
    double cpu_MHz;                         // Current processor frequency
    long ram_total;                         // Total RAM (KB)
    long ram_free;                          // Free RAM (KB)
    int ram_usage;                          // Percentage of RAM in use
} hw_entry;

typedef struct os_entry {
    char * hostname;                        // Hostname of the machine
    char * architecture;                    // OS architecture
    char * os_name;                         // OS name
    char * os_release;                      // OS release
    char * os_version;                      // OS version
    char * os_codename;                     // OS version codename
    char * os_major;                        // Major release version
    char * os_minor;                        // Minor release version
    char * os_build;                        // Optional build-specific
    char * os_platform;                     // OS platform
    char * sysname;                         // System name
    char * release;                         // Release name
    char * version;                         // Release version
} os_entry;

typedef struct net_addr {
    char ** address;                        // IPv4/IPv6 address
    char ** netmask;                        // Netmask address
    char ** broadcast;                      // Broadcast address
    int metric;                             // Metric
    char * gateway;                         // Default gateway
    char * dhcp;                            // DHCP status
} net_addr;

typedef struct interface_entry_data {
    char * name;                            // Interface name
    char * adapter;                         // Physical adapter name
    char * type;                            // Network adapter
    char * state;                           // State of the interface
    char * mac;                             // MAC Address
    int mtu;                                // Maximum Transmission Unit

    int tx_packets;                         // Transmitted packets
    int rx_packets;                         // Received packets
    int tx_bytes;                           // Transmitted bytes
    int rx_bytes;                           // Received bytes
    int tx_errors;                          // Transmission errors
    int rx_errors;                          // Reception errors
    int tx_dropped;                         // Dropped transmission packets
    int rx_dropped;                         // Dropped reception packets

    struct net_addr * ipv4;
    struct net_addr * ipv6;

    int enabled;
} interface_entry_data;

typedef struct program_entry_data {
    char * format;                          // Format of the package
    char * name;                            // Name of the package

    char * priority;                        // Priority of the package
    char * group;                           // Section of the package
    long size;                              // Size of the installed package in bytes
    char * vendor;                          // Vendor name
    char * install_time;                    // Date when the package was installed
    char * version;                         // Version of the package
    char * architecture;                    // Architecture of the package
    char * multi_arch;                      // Multiarchitecture support
    char * source;                          // Source of the package
    char * description;                     // Description of the package
    char * location;                        // Location of the package

    int installed;
} program_entry_data;

typedef struct hotfix_entry_data {
    char * hotfix;                          // Hotfix name

    int installed;
} hotfix_entry_data;

typedef struct port_entry_data {
    char * protocol;                        // Protocol of the port

    char * local_ip;                        // Local IP
    int local_port;                         // Local port
    char * remote_ip;                       // Remote IP
    int remote_port;                        // Remote port

    int tx_queue;                           // Packets pending to be transmitted
    int rx_queue;                           // Packets at the receiver queue
    int inode;                              // Inode of the port

    char * state;                           // State of the port

    int pid;                                // PID owner of the opened port
    char * process;                         // Name of the PID

    int opened;
} port_entry_data;

typedef struct process_entry_data {
    int pid;                                // PID of the process
    int ppid;                               // PPID of the process
    char * name;                            // Name of the process
    char * cmd;                             // Command executed
    char ** argvs;                          // Arguments of the process
    char * state;                           // State of the process

    char * euser;                           // Effective user
    char * ruser;                           // Real user
    char * suser;                           // Saved-set user
    char * egroup;                          // Effective group
    char * rgroup;                          // Real group
    char * sgroup;                          // Saved-set group
    char * fgroup;                          // Filesystem group name

    int priority;                           // Kernel scheduling priority
    int nice;                               // Nice value of the process

    long size;                              // Size of the process
    long vm_size;                           // Total VM size (KB)
    long resident;                          // Residen size of the process in bytes
    long share;                             // Shared memory

    long long start_time;                   // Time when the process started
    long long utime;                        // Time spent executing user code
    long long stime;                        // Time spent executing system code

    int pgrp;                               // Process group
    int session;                            // Session of the process
    int nlwp;                               // Number of light weight processes
    int tgid;                               // Thread Group ID
    int tty;                                // Number of TTY of the process
    int processor;                          // Number of the processor

    int running;
} process_entry_data;

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
    time_t hw_next_time;                    // Absolute time for next hardware scan
    time_t os_next_time;                    // Absolute time for next operative system scan
    time_t interfaces_next_time;            // Absolute time for next interfaces scan
    time_t programs_next_time;              // Absolute time for next packages/programs scan
    time_t hotfixes_next_time;              // Absolute time for next hotfixes scan
    time_t ports_next_time;                 // Absolute time for next ports scan
    time_t processes_next_time;             // Absolute time for next processes scan
} wm_sys_state_t;

typedef struct wm_sys_t {
    unsigned int default_interval;          // Default time interval between cycles (seconds)
    unsigned int hw_interval;               // Time interval for hardware inventory (seconds)
    unsigned int os_interval;               // Time interval for operative system inventory (seconds)
    unsigned int interfaces_interval;       // Time interval for interfaces inventory (seconds)
    unsigned int programs_interval;         // Time interval for packages/programs inventory (seconds)
    unsigned int hotfixes_interval;         // Time interval for hotfixes inventory (seconds)
    unsigned int ports_interval;            // Time interval for ports inventory (seconds)
    unsigned int processes_interval;        // Time interval for processes inventory (seconds)

    wm_sys_flags_t flags;                   // Flag bitfield
    wm_sys_state_t state;                   // Running state

    hw_entry * hw_data;                     // Hardware data store
    os_entry * os_data;                     // OS data store
    rb_tree * interfaces_entry;             // Interfaces data store
    rb_tree * programs_entry;               // Packages data store
    rb_tree * hotfixes_entry;               // Hotfixes data store
    rb_tree * ports_entry;                  // Ports data store
    rb_tree * processes_entry;              // Processes data store

    pthread_mutex_t hardware_mutex;
    pthread_mutex_t os_mutex;
    pthread_mutex_t interfaces_entry_mutex;
    pthread_mutex_t programs_entry_mutex;
    pthread_mutex_t hotfixes_entry_mutex;
    pthread_mutex_t ports_entry_mutex;
    pthread_mutex_t processes_entry_mutex;
} wm_sys_t;

struct link_stats {
    unsigned int rx_packets;
    unsigned int tx_packets;
    unsigned int rx_bytes;
    unsigned int tx_bytes;
    unsigned int rx_errors;
    unsigned int tx_errors;
    unsigned int rx_dropped;
    unsigned int tx_dropped;
};

typedef struct gateway {
    char *addr;
    int isdefault;
} gateway;

typedef struct rpm_data {
    char *tag;
    int type;
    int offset;
    int count;
    struct rpm_data *next;
} rpm_data;

extern const wm_context WM_SYS_CONTEXT;     // Context
extern wm_sys_t *sys;                       // Configuration

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module);

// Opened ports inventory for Linux
void sys_ports_linux(int queue_fd, const char* WM_SYS_LOCATION, int check_all);

// Opened ports inventory for Windows
void sys_ports_windows(const char* LOCATION, int check_all);

// Opened ports inventory for MAC OS X
#ifdef __MACH__
    void sys_ports_mac(int queue_fd, const char* WM_SYS_LOCATION, int check_all);
#endif

// Installed packages inventory for Linux
void sys_packages_linux(int queue_fd, const char* WM_SYS_LOCATION);
void sys_deb_packages(int queue_fd, const char* WM_SYS_LOCATION);
void sys_rpm_packages(int queue_fd, const char* WM_SYS_LOCATION);

#ifdef WIN32
// Installed programs inventory for Windows
void sys_programs_windows(const char* LOCATION);

// Installed hotfixes inventory for Windows
void sys_hotfixes(const char* LOCATION);

// Network inventory for Windows XP
interface_entry_data * get_network_xp(PIP_ADAPTER_ADDRESSES pCurrAddresses, PIP_ADAPTER_INFO AdapterInfo);

// Get values about a single program from the registry
void read_win_program(const char * sec_key, int arch, int root_key, int usec, const char * timestamp, const char * LOCATION);

// Get values about a single hotfix from the registry
void send_hotfix(const char *hotfix, int usec, const char *timestamp, const char *LOCATION);

// List installed programs from the registry
void list_programs(HKEY hKey, int arch, const char * root_key, int usec, const char * timestamp, const char * LOCATION);

// List installed hotfixes from the registry
void list_hotfixes(HKEY hKey, int usec, const char *timestamp, const char *LOCATION);

// List Windows users from the registry
void list_users(HKEY hKey, int usec, const char * timestamp, const char * LOCATION);
#endif

#if defined(__FreeBSD__) || defined(__MACH__)
// Installed programs inventory for BSD based systems
void sys_packages_bsd(int queue_fd, const char* LOCATION);

#endif

#ifdef __MACH__
int getGatewayList(OSHash *gateway_list);

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
#ifdef __MACH__
void sys_proc_mac(int queue_fd, const char* LOCATION);
#endif

// Read string from a byte array until find a NULL byte
char* read_string(u_int8_t* bytes);

// Read four bytes and retrieve its decimal value
int four_bytes_to_int32(u_int8_t* bytes);

// Read index entry from a RPM header
int read_entry(u_int8_t* bytes, rpm_data *info);

// Get the inventory for a network interface in the object passed as parameter
struct ifaddrs;
interface_entry_data * getNetworkIface_linux(char *iface_name, struct ifaddrs *ifaddr);

interface_entry_data * getNetworkIface_bsd(char *iface_name, struct ifaddrs *ifaddrs_ptr, __attribute__((unused)) gateway *gate);
// Create the interface list
int getIfaceslist(char **ifaces_list, struct ifaddrs *ifaddr);

// Generate a random ID
int wm_sys_get_random_id();

// Initialize datastores
void sys_initialize_datastores();

// Initialize hardware data
hw_entry * init_hw_data();
// Initialize operative system data
os_entry * init_os_data();
// Initialize network address
net_addr * init_net_addr();
// Initialize interface data
interface_entry_data * init_interface_data_entry();
// Initialize process data
program_entry_data * init_program_data_entry();
// Initialize hotfix data
hotfix_entry_data * init_hotfix_data_entry();
// Initialize port data
port_entry_data * init_port_data_entry();
// Initialize process data
process_entry_data * init_process_data_entry();

// Free hardware data
void free_hw_data(hw_entry * data);
// Free operative system data
void free_os_data(os_entry * data);
// Free interface data
void free_interface_data(interface_entry_data * data);
// Free program data
void free_program_data(program_entry_data * data);
// Free hotfix data
void free_hotfix_data(hotfix_entry_data * data);
// Free port data
void free_port_data(port_entry_data * data);
// Free process data
void free_process_data(process_entry_data * data);

// Analyze if update the hardware information
char * analyze_hw(hw_entry * entry_data, const char * timestamp);
// Analyze if update the operative system information
char * analyze_os(os_entry * entry_data, const char * timestamp);
// Analyze if insert new interface or update an existing one
char * analyze_interface(interface_entry_data * entry_data, const char * timestamp);
// Analyze if insert new program or update an existing one
char * analyze_program(program_entry_data * entry_data, const char * timestamp);
// Analyze if insert new hotfix or update an existing one
char * analyze_hotfix(hotfix_entry_data * entry_data, const char * timestamp);
// Analyze if insert new port or update an existing one
char * analyze_port(port_entry_data * entry_data, const char * timestamp);
// Analyze if insert new process or update an existing one
char * analyze_process(process_entry_data * entry_data, const char * timestamp);

// Deletes the disabled interfaces from the hash table
void check_disabled_interfaces();
// Deletes the uninstalled programs from the hash table
void check_uninstalled_programs();
// Deletes the uninstalled hotfixes from the hash table
void check_uninstalled_hotfixes();
// Deletes the closed ports from the hash table
void check_closed_ports();
// Deletes the terminated processes from the hash table
void check_terminated_processes();

// Insert process into hash table
int insert_entry(rb_tree * tree, const char * key, void * data);
// Update process to hash table
int update_entry(rb_tree * tree, const char * key, void * data);
// Delete process from hash table
void delete_entry(rb_tree * tree, const char * key);

// Print keys from hash table
void print_rbtree(rb_tree * tree, pthread_mutex_t mutex);

// Send a sys scan event
void sys_send_scan_event(sys_scan_event type);

/**
 * @brief Produce a hardware change JSON event
 *
 * {
 *   type:                  "hardware"
 *   data: {
 *     type:                "added"|"modified"
 *     timestamp:           string
 *     changed_attributes:  array   hw_json_compare()           [Only if old_data]
 *     old_attributes:      object  hw_json_attributes()        [Only if old_data]
 *     attributes:          object  hw_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous hardware state.
 * @param new_data Current hardware state.
 * @param type Type of event: added or modified.
 * @param timestamp Time of the event.
 * @return Hardware event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * hw_json_event(hw_entry * old_data, hw_entry * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create hardware attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - board_serial
 * - cpu_name
 * - cpu_cores
 * - cpu_MHz
 * - ram_total
 * - ram_free
 * - ram_usage
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * hw_json_compare(hw_entry * old_data, hw_entry * new_data);

/**
 * @brief Create hardware attribute set JSON from a hw_entry structure
 *
 * Format:
 * {
 *   board_serial:  string
 *   cpu_name:      string
 *   cpu_cores:     number
 *   cpu_MHz:       number
 *   ram_total:     number
 *   ram_free:      number
 *   ram_usage:     number
 * }
 *
 * @param data Pointer to a hw_entry structure.
 * @return Pointer to cJSON structure.
 */
cJSON * hw_json_attributes(hw_entry * data);

/**
 * @brief Produce an operative system change JSON event
 *
 * {
 *   type:                  "OS"
 *   data: {
 *     type:                "added"|"modified"
 *     timestamp:           string
 *     changed_attributes:  array   os_json_compare()           [Only if old_data]
 *     old_attributes:      object  os_json_attributes()        [Only if old_data]
 *     attributes:          object  os_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous operative system state.
 * @param new_data Current operative system state.
 * @param type Type of event: added or modified.
 * @param timestamp Time of the event.
 * @return Operative System event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * os_json_event(os_entry * old_data, os_entry * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create operative system attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - hostname
 * - architecture
 * - os_name
 * - os_release
 * - os_version
 * - os_codename
 * - os_major
 * - os_minor
 * - os_build
 * - os_platform
 * - sysname
 * - release
 * - version
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * os_json_compare(os_entry * old_data, os_entry * new_data);

/**
 * @brief Create operative system attribute set JSON from a os_entry structure
 *
 * Format:
 * {
 *   hostname:      string
 *   architecture:  string
 *   os_name:       string
 *   os_release:    string
 *   os_version:    string
 *   os_codename:   string
 *   os_major:      string
 *   os_minor:      string
 *   os_build:      string
 *   os_platform:   string
 *   sysname:       string
 *   release:       string
 *   version:       string
 * }
 *
 * @param data Pointer to a os_entry structure.
 * @return Pointer to cJSON structure.
 */
cJSON * os_json_attributes(os_entry * data);

/**
 * @brief Produce an interface change JSON event
 *
 * {
 *   type:                  "network"
 *   data: {
 *     type:                "added"|"modified"|"deleted"
 *     timestamp:           string
 *     changed_attributes:  array   interface_json_compare()    [Only if old_data]
 *     old_attributes:      object  interface_json_attributes() [Only if old_data]
 *     attributes:          object  interface_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous interface state.
 * @param new_data Current interface state.
 * @param type Type of event: added, modified or deleted.
 * @param timestamp Time of the event.
 * @return Interface event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * interface_json_event(interface_entry_data * old_data, interface_entry_data * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create interface attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - name
 * - adapter
 * - type
 * - state
 * - mac
 * - ipv4
 * - ipv4_address
 * - ipv4_netmask
 * - ipv4_broadcast
 * - ipv4_gateway
 * - ipv4_dhcp
 * - ipv4_metric
 * - ipv6
 * - ipv6_address
 * - ipv6_netmask
 * - ipv6_broadcast
 * - ipv6_gateway
 * - ipv6_dhcp
 * - ipv6_metric
 * - mtu
 * - tx_packets
 * - rx_packets
 * - tx_bytes
 * - rx_bytes
 * - tx_errors
 * - rx_errors
 * - tx_dropped
 * - rx_dropped
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * interface_json_compare(interface_entry_data * old_data, interface_entry_data * new_data);

/**
 * @brief Create interface attribute set JSON from a interface_entry_data structure
 *
 * Format:
 * {
 *   name:          string
 *   adapter:       string
 *   type:          string
 *   state:         string
 *   mac:           string
 *   ipv4:          object
 *    address:      array
 *    netmask:      array
 *    broadcast:    array
 *    gateway:      string
 *    dhcp:         string
 *    metric:       number
 *   ipv6:          object
 *    address:      array
 *    netmask:      array
 *    broadcast:    array
 *    gateway:      string
 *    dhcp:         string
 *    metric:       number
 *   mtu:           number
 *   tx_packets:    number
 *   rx_packets:    number
 *   tx_bytes:      number
 *   rx_bytes:      number
 *   tx_errors:     number
 *   rx_errors:     number
 *   tx_dropped:    number
 *   rx_dropped:    number
 * }
 *
 * @param data Pointer to a interface_entry_data structure.
 * @return Pointer to cJSON structure.
 */
cJSON * interface_json_attributes(interface_entry_data * data);

/**
 * @brief Produce a program change JSON event
 *
 * {
 *   type:                  "program"
 *   data: {
 *     type:                "added"|"modified"|"deleted"
 *     timestamp:           string
 *     changed_attributes:  array   program_json_compare()      [Only if old_data]
 *     old_attributes:      object  program_json_attributes()   [Only if old_data]
 *     attributes:          object  program_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous program state.
 * @param new_data Current program state.
 * @param type Type of event: added, modified or deleted.
 * @param timestamp Time of the event.
 * @return Program event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * program_json_event(program_entry_data * old_data, program_entry_data * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create program attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - format
 * - name
 * - priority
 * - group
 * - vendor
 * - install_time
 * - version
 * - architecture
 * - multi_arch
 * - source
 * - description
 * - location
 * - size
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * program_json_compare(program_entry_data * old_data, program_entry_data * new_data);

/**
 * @brief Create program attribute set JSON from a program_entry_data structure
 *
 * Format:
 * {
 *   format:        string
 *   name:          string
 *   priority:      string
 *   group:         string
 *   vendor:        string
 *   install_time:  string
 *   version:       string
 *   architecture:  string
 *   multi_arch:    string
 *   source:        string
 *   description:   string
 *   location:      string
 *   size:          number
 * }
 *
 * @param data Pointer to a program_entry_data structure.
 * @return Pointer to cJSON structure.
 */
cJSON * program_json_attributes(program_entry_data * data);

/**
 * @brief Produce a hotfix change JSON event
 *
 * {
 *   type:                  "hotfix"
 *   data: {
 *     type:                "added"|"modified"|"deleted"
 *     timestamp:           string
 *     changed_attributes:  array   hotfix_json_compare()       [Only if old_data]
 *     old_attributes:      object  hotfix_json_attributes()    [Only if old_data]
 *     attributes:          object  hotfix_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous hotfix state.
 * @param new_data Current hotfix state.
 * @param type Type of event: added, modified or deleted.
 * @param timestamp Time of the event.
 * @return Hotfix event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * hotfix_json_event(hotfix_entry_data * old_data, hotfix_entry_data * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create hotfix attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - hotfix
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * hotfix_json_compare(hotfix_entry_data * old_data, hotfix_entry_data * new_data);

/**
 * @brief Create hotfix attribute set JSON from a hotfix_entry_data structure
 *
 * Format:
 * {
 *   hotfix:        string
 * }
 *
 * @param data Pointer to a hotfix_entry_data structure.
 * @return Pointer to cJSON structure.
 */
cJSON * hotfix_json_attributes(hotfix_entry_data * data);

/**
 * @brief Produce a port change JSON event
 *
 * {
 *   type:                  "port"
 *   data: {
 *     type:                "added"|"modified"|"deleted"
 *     timestamp:           string
 *     changed_attributes:  array   port_json_compare()         [Only if old_data]
 *     old_attributes:      object  port_json_attributes()      [Only if old_data]
 *     attributes:          object  port_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous port state.
 * @param new_data Current port state.
 * @param type Type of event: added, modified or deleted.
 * @param timestamp Time of the event.
 * @return Port event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * port_json_event(port_entry_data * old_data, port_entry_data * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create port attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - protocol
 * - local_ip
 * - remote_ip
 * - state
 * - process
 * - local_port
 * - remote_port
 * - tx_queue
 * - rx_queue
 * - inode
 * - pid
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * port_json_compare(port_entry_data * old_data, port_entry_data * new_data);

/**
 * @brief Create port attribute set JSON from a port_entry_data structure
 *
 * Format:
 * {
 *   protocol:      string
 *   local_ip:      string
 *   remote_ip:     string
 *   state:         string
 *   process:       string
 *   local_port:    number
 *   remote_port:   number
 *   tx_queue:      number
 *   rx_queue:      number
 *   inode:         number
 *   pid:           number
 * }
 *
 * @param data Pointer to a port_entry_data structure.
 * @return Pointer to cJSON structure.
 */
cJSON * port_json_attributes(port_entry_data * data);

/**
 * @brief Produce a process change JSON event
 *
 * {
 *   type:                  "process"
 *   data: {
 *     type:                "added"|"modified"|"deleted"
 *     timestamp:           string
 *     changed_attributes:  array   process_json_compare()      [Only if old_data]
 *     old_attributes:      object  process_json_attributes()   [Only if old_data]
 *     attributes:          object  process_json_attributes()
 *   }
 * }
 *
 * @param old_data Previous process state.
 * @param new_data Current process state.
 * @param type Type of event: added, modified or deleted.
 * @param timestamp Time of the event.
 * @return Process event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON * process_json_event(process_entry_data * old_data, process_entry_data * new_data, sys_event_type type, const char * timestamp);

/**
 * @brief Create process attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - name
 * - cmd
 * - argvs
 * - state
 * - euser
 * - ruser
 * - suser
 * - egroup
 * - rgroup
 * - sgroup
 * - fgroup
 * - pid
 * - ppid
 * - priority
 * - nice
 * - size
 * - vm_size
 * - resident
 * - share
 * - start_time
 * - utime
 * - stime
 * - pgrp
 * - session
 * - nlwp
 * - tgid
 * - tty
 * - processor
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * process_json_compare(process_entry_data * old_data, process_entry_data * new_data);

/**
 * @brief Create process attribute set JSON from a process_entry_data structure
 *
 * Format:
 * {
 *   name:          string
 *   cmd:           string
 *   argvs:         array
 *   state:         string
 *   euser:         string
 *   ruser:         string
 *   suser:         string
 *   egroup:        string
 *   rgroup:        string
 *   sgroup:        string
 *   fgroup:        string
 *   pid:           number
 *   ppid:          number
 *   priority:      number
 *   nice:          number
 *   size:          number
 *   vm_size:       number
 *   resident:      number
 *   share:         number
 *   start_time:    number
 *   utime:         number
 *   stime:         number
 *   pgrp:          number
 *   session:       number
 *   nlwp:          number
 *   tgid:          number
 *   tty:           number
 *   processor:     number
 * }
 *
 * @param data Pointer to a process_entry_data structure.
 * @return Pointer to cJSON structure.
 */
cJSON * process_json_attributes(process_entry_data * data);

/**
 * @brief Create sys scan JSON event
 *
 * Format:
 * {
 *   type:          "hardware_scan"|"OS_scan"|"network_scan"|"program_scan"|"hotfix_scan"|"port_scan"|"process_scan"
 *   data: {
 *     timestamp:   number
 *     items:       number
 *   }
 * }
 *
 * @param type Event type (hardware, OS, network, program, hotfix, port or process).
 * @param timestamp Datetime in UNIX epoch.
 * @param items Number of items stored in the inventory.
 * @return cJSON object pointer.
 */

cJSON * sys_json_scan_event(sys_scan_event type, time_t timestamp, int items);

#endif
#endif

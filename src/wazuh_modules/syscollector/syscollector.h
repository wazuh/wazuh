/*
 * Wazuh Module for System inventory
 * Copyright (C) 2015-2019, Wazuh Inc.
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

typedef enum sys_scan_event {
    HW_SCAN,
    OS_SCAN,
    IFACE_SCAN,
    PKG_SCAN,
    HFIX_SCAN,
    PORT_SCAN,
    PROC_SCAN
} sys_scan_event;

typedef enum hw_event_type {
    HW_ADD,
    HW_MODIFY
} hw_event_type;

typedef enum os_event_type {
    OS_ADD,
    OS_MODIFY
} os_event_type;

typedef enum interface_event_type {
    IFACE_ADD,
    IFACE_MODIFY,
    IFACE_DELETE
} interface_event_type;

typedef enum program_event_type {
    PKG_ADD,
    PKG_MODIFY,
    PKG_DELETE
} program_event_type;

typedef enum hotfix_event_type {
    HFIX_ADD,
    HFIX_MODIFY,
    HFIX_DELETE
} hotfix_event_type;

typedef enum port_event_type {
    PORT_ADD,
    PORT_MODIFY,
    PORT_DELETE
} port_event_type;

typedef enum process_event_type {
    PROC_ADD,
    PROC_MODIFY,
    PROC_DELETE
} process_event_type;

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

//
cJSON * hw_json_event(hw_entry * old_data, hw_entry * new_data, hw_event_type type, const char * timestamp);
//
cJSON * hw_json_compare(hw_entry * old_data, hw_entry * new_data);
//
cJSON * hw_json_attributes(hw_entry * data);
//
cJSON * os_json_event(os_entry * old_data, os_entry * new_data, os_event_type type, const char * timestamp);
//
cJSON * os_json_compare(os_entry * old_data, os_entry * new_data);
//
cJSON * os_json_attributes(os_entry * data);
//
cJSON * interface_json_event(interface_entry_data * old_data, interface_entry_data * new_data, interface_event_type type, const char * timestamp);
//
cJSON * interface_compare(interface_entry_data * old_data, interface_entry_data * new_data);
//
cJSON * interface_json_attributes(interface_entry_data * data);
//
cJSON * program_json_event(program_entry_data * old_data, program_entry_data * new_data, program_event_type type, const char * timestamp);
//
cJSON * program_json_compare(program_entry_data * old_data, program_entry_data * new_data);
//
cJSON * program_json_attributes(program_entry_data * data);
//
cJSON * hotfix_json_event(hotfix_entry_data * old_data, hotfix_entry_data * new_data, hotfix_event_type type, const char * timestamp);
//
cJSON * hotfix_json_compare(hotfix_entry_data * old_data, hotfix_entry_data * new_data);
//
cJSON * hotfix_json_attributes(hotfix_entry_data * data);
//
cJSON * port_json_event(port_entry_data * old_data, port_entry_data * new_data, port_event_type type, const char * timestamp);
//
cJSON * port_json_compare(port_entry_data * old_data, port_entry_data * new_data);
//
cJSON * port_json_attributes(port_entry_data * data);
//
cJSON * process_json_event(process_entry_data * old_data, process_entry_data * new_data, process_event_type type, const char * timestamp);
//
cJSON * process_json_compare(process_entry_data * old_data, process_entry_data * new_data);
//
cJSON * process_json_attributes(process_entry_data * data);

#endif
#endif

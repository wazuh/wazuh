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

typedef struct hw_entry {
    char * board_serial;
    char * cpu_name;
    int cpu_cores;
    double cpu_MHz;
    long ram_total;
    long ram_free;
    int ram_usage;
} hw_entry;

typedef struct os_entry {
    char * hostname;
    char * architecture;
    char * os_name;
    char * os_release;
    char * os_version;
    char * os_codename;
    char * os_major;
    char * os_minor;
    char * os_build;
    char * os_platform;
    char * sysname;
    char * release;
    char * version;
} os_entry;

typedef struct net_addr {
    char ** address;
    char ** netmask;
    char ** broadcast;
    int metric;
    char * gateway;
    char * dhcp;
} net_addr;

typedef struct interface_entry_data {
    char * name;
    char * adapter;
    char * type;
    char * state;
    char * mac;
    int mtu;

    int tx_packets;
    int rx_packets;
    int tx_bytes;
    int rx_bytes;
    int tx_errors;
    int rx_errors;
    int tx_dropped;
    int rx_dropped;

    struct net_addr * ipv4;
    struct net_addr * ipv6;

    int enabled;
} interface_entry_data;

typedef struct program_entry_data {
    char * format;
    char * name;

    char * priority;
    char * group;
    long size;
    char * vendor;
    char * install_time;
    char * version;
    char * architecture;
    char * multi_arch;
    char * source;
    char * description;
    char * location;

    int installed;
} program_entry_data;

typedef struct hotfix_entry_data {
    char * hotfix;

    int installed;
} hotfix_entry_data;

typedef struct port_entry_data {
    char * protocol;

    char * local_ip;
    int local_port;
    char * remote_ip;
    int remote_port;

    int tx_queue;
    int rx_queue;
    int inode;

    char * state;

    int pid;
    char * process;

    int opened;
} port_entry_data;

typedef struct process_entry_data {
    int pid;
    int ppid;
    char * name;
    char * cmd;
    char ** argvs;
    char * state;

    char * euser;
    char * ruser;
    char * suser;
    char * egroup;
    char * rgroup;
    char * sgroup;
    char * fgroup;

    int priority;
    int nice;

    long size;
    long vm_size;
    long resident;
    long share;

    long long start_time;
    long long utime;
    long long stime;

    int pgrp;
    int session;
    int nlwp;
    int tgid;
    int tty;
    int processor;

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
    time_t next_time;                       // Absolute time for next scan
} wm_sys_state_t;

typedef struct wm_sys_t {
    unsigned int interval;                  // Time interval between cycles (seconds)
    wm_sys_flags_t flags;                   // Flag bitfield
    wm_sys_state_t state;                   // Running state

    hw_entry * hw_data;
    os_entry * os_data;
    rb_tree * interfaces_entry;
    rb_tree * programs_entry;
    rb_tree * hotfixes_entry;
    rb_tree * ports_entry;
    rb_tree * processes_entry;

    pthread_mutex_t hardware_mutex;
    pthread_mutex_t os_mutex;
    pthread_mutex_t interfaces_entry_mutex;
    pthread_mutex_t programs_entry_mutex;
    pthread_mutex_t hotfixes_entry_mutex;
    pthread_mutex_t ports_entry_mutex;
    pthread_mutex_t processes_entry_mutex;
} wm_sys_t;

struct link_stats {
    unsigned int rx_packets;    /* total packets received */
    unsigned int tx_packets;    /* total packets transmitted */
    unsigned int rx_bytes;      /* total bytes received */
    unsigned int tx_bytes;      /* total bytes transmitted */
    unsigned int rx_errors;     /* bad packets received */
    unsigned int tx_errors;     /* packet transmit problems */
    unsigned int rx_dropped;    /* no space in linux buffers */
    unsigned int tx_dropped;    /* no space available in linux */
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
char * sys_deb_packages(int queue_fd, const char* WM_SYS_LOCATION, int random_id);
char * sys_rpm_packages(int queue_fd, const char* WM_SYS_LOCATION, int random_id);

#ifdef WIN32
// Installed programs inventory for Windows
void sys_programs_windows(const char* LOCATION);

// Installed hotfixes inventory for Windows
void sys_hotfixes(const char* LOCATION);

// Network inventory for Windows XP
interface_entry_data * get_network_xp(PIP_ADAPTER_ADDRESSES pCurrAddresses, PIP_ADAPTER_INFO AdapterInfo);

// Get values about a single program from the registry
void read_win_program(const char * sec_key, int arch, int root_key, int usec, const char * timestamp, int ID, const char * LOCATION);

// Get values about a single hotfix from the registry
void send_hotfix(const char *hotfix, int usec, const char *timestamp, int ID, const char *LOCATION);

// List installed programs from the registry
void list_programs(HKEY hKey, int arch, const char * root_key, int usec, const char * timestamp, int ID, const char * LOCATION);

// List installed hotfixes from the registry
void list_hotfixes(HKEY hKey, int usec, const char *timestamp, int ID, const char *LOCATION);

// List Windows users from the registry
void list_users(HKEY hKey, int usec, const char * timestamp, int ID, const char * LOCATION);
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
cJSON * analyze_hw(hw_entry * entry_data, int random_id, const char * timestamp);
// Analyze if update the operative system information
cJSON * analyze_os(os_entry * entry_data, int random_id, const char * timestamp);
// Analyze if insert new interface or update an existing one
cJSON * analyze_interface(interface_entry_data * entry_data, int random_id, const char * timestamp);
// Analyze if insert new program or update an existing one
cJSON * analyze_program(program_entry_data * entry_data, int random_id, const char * timestamp);
// Analyze if insert new hotfix or update an existing one
cJSON * analyze_hotfix(hotfix_entry_data * entry_data, int random_id, const char * timestamp);
// Analyze if insert new port or update an existing one
cJSON * analyze_port(port_entry_data * entry_data, int random_id, const char * timestamp);
// Analyze if insert new process or update an existing one
cJSON * analyze_process(process_entry_data * entry_data, int random_id, const char * timestamp);

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
cJSON * hw_json_event(hw_entry * new_data, int random_id, const char * timestamp);
//
cJSON * os_json_event(os_entry * new_data, int random_id, const char * timestamp);
//
cJSON * interface_json_event(interface_entry_data * new_data, int random_id, const char * timestamp);
//
cJSON * program_json_event(program_entry_data * new_data, int random_id, const char * timestamp);
//
cJSON * hotfix_json_event(hotfix_entry_data * new_data, int random_id, const char * timestamp);
//
cJSON * port_json_event(port_entry_data * new_data, int random_id, const char * timestamp);
//
cJSON * process_json_event(process_entry_data * new_data, int random_id, const char * timestamp);

#endif
#endif

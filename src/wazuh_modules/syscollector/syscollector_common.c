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

#include "syscollector.h"
#include <errno.h>

#ifdef UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

#define RUN_HW        000000001
#define RUN_OS        000000002
#define RUN_IFACE     000000004
#define RUN_PKG       000000010
#define RUN_HFIX      000000020
#define RUN_PORT      000000040
#define RUN_PROC      000000100

static const char *SYS_SCAN_EVENT[] = {
    "hardware_scan",
    "OS_scan",
    "network_scan",
    "program_scan",
    "hotfix_scan",
    "port_scan",
    "process_scan"
};

static const char *SYS_EVENT_TYPE[] = {
    "added",
    "modified",
    "deleted"
};

wm_sys_t *sys = NULL;                           // Definition of global config

static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
static void wm_sys_destroy(wm_sys_t *sys);      // Destroy data
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON *wm_sys_dump(const wm_sys_t *sys);

// Syscollector module context definition

const wm_context WM_SYS_CONTEXT = {
    "inventory",
    (wm_routine)wm_sys_main,
    (wm_routine)(void *)wm_sys_destroy,
    (cJSON * (*)(const void *))wm_sys_dump
};

#ifndef WIN32
int queue_fd;                                   // Output queue file descriptor
#endif

static void wm_sys_setup(wm_sys_t *_sys);       // Setup module
static void wm_sys_check();                     // Check configuration, disable flag
#ifndef WIN32
static void wm_sys_cleanup();                   // Cleanup function, doesn't overwrite wm_cleanup
#endif

time_t get_sleep_time(int *run);      // Function to get the next inventory scan time
void update_next_time(int *run);      // Update the next scan time of the inventories

// Module main function. It won't return

void* wm_sys_main(wm_sys_t *sys) {

    time_t time_start = 0;
    time_t time_sleep = 0;
    int run = 0;

    // Check configuration and show debug information

    wm_sys_setup(sys);

    sys_initialize_datastores();

    mtinfo(WM_SYS_LOGTAG, "Module started.");

    time_start = time(NULL);
    sys->state.hw_next_time = time_start;
    sys->state.os_next_time = time_start;
    sys->state.interfaces_next_time = time_start;
    sys->state.programs_next_time = time_start;
    sys->state.hotfixes_next_time = time_start;
    sys->state.ports_next_time = time_start;
    sys->state.processes_next_time = time_start;

    // First sleeping

    if (!sys->flags.scan_on_start) {
        // On first run, take into account the interval of time specified
        sys->state.hw_next_time += sys->hw_interval;
        sys->state.os_next_time += sys->os_interval;
        sys->state.interfaces_next_time += sys->interfaces_interval;
        sys->state.programs_next_time += sys->programs_interval;
        sys->state.hotfixes_next_time += sys->hotfixes_interval;
        sys->state.ports_next_time += sys->ports_interval;
        sys->state.processes_next_time += sys->processes_interval;

        if (time_sleep = get_sleep_time(&run), time_sleep > 0) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            w_time_delay(1000 * time_sleep);
        }
    } else {
        // Wait for Wazuh DB start
        w_time_delay(1000);
        run |= (RUN_HW | RUN_OS | RUN_IFACE | RUN_PKG | RUN_PORT | RUN_PROC);
    #ifdef WIN32
        run |= RUN_HFIX;
    #endif
    }

    // Main loop

    while (1) {

        mtinfo(WM_SYS_LOGTAG, "Starting evaluation.");

        /* Network inventory */
        if (sys->flags.netinfo && (run & RUN_IFACE)){
            #ifdef WIN32
                sys_network_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_network_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                sys_network_bsd(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.netinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Network inventory is not available for this OS version.");
            #endif
            #ifdef DEBUG
                print_rbtree(sys->interfaces_entry, sys->interfaces_entry_mutex);
            #endif
            sys_send_scan_event(IFACE_SCAN);
        }

        /* Operating System inventory */
        if (sys->flags.osinfo && (run & RUN_OS)){
            #ifdef WIN32
                sys_os_windows(WM_SYS_LOCATION);
            #else
                sys_os_unix(queue_fd, WM_SYS_LOCATION);
            #endif
            sys_send_scan_event(OS_SCAN);
        }

        /* Hardware inventory */
        if (sys->flags.hwinfo && (run & RUN_HW)){
            #if defined(WIN32)
                sys_hw_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_hw_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__MACH__)
                sys_hw_bsd(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.hwinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Hardware inventory is not available for this OS version.");
            #endif
            sys_send_scan_event(HW_SCAN);
        }

        /* Installed programs inventory */
        if (sys->flags.programinfo && (run & RUN_PKG)){
            #if defined(WIN32)
                sys_programs_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_packages_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__FreeBSD__) || defined(__MACH__)
                sys_packages_bsd(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.programinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Packages inventory is not available for this OS version.");
            #endif
            #ifdef DEBUG
                print_rbtree(sys->programs_entry, sys->programs_entry_mutex);
            #endif
            sys_send_scan_event(PKG_SCAN);
        }

        /* Installed hotfixes inventory */
        if (sys->flags.hotfixinfo && (run & RUN_HFIX)) {
            #ifdef WIN32
                sys_hotfixes(WM_SYS_LOCATION);
            #endif
            #ifdef DEBUG
                print_rbtree(sys->hotfixes_entry, sys->hotfixes_entry_mutex);
            #endif
            sys_send_scan_event(HFIX_SCAN);
        }
        /* Opened ports inventory */
        if (sys->flags.portsinfo && (run & RUN_PORT)){
            #if defined(WIN32)
                sys_ports_windows(WM_SYS_LOCATION, sys->flags.allports);
            #elif defined(__linux__)
                sys_ports_linux(queue_fd, WM_SYS_LOCATION, sys->flags.allports);
            #elif defined(__MACH__)
                sys_ports_mac(queue_fd, WM_SYS_LOCATION, sys->flags.allports);
            #else
                sys->flags.portsinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Opened ports inventory is not available for this OS version.");
            #endif
            #ifdef DEBUG
                print_rbtree(sys->ports_entry, sys->ports_entry_mutex);
            #endif
            sys_send_scan_event(PORT_SCAN);
        }

        /* Running processes inventory */
        if (sys->flags.procinfo && (run & RUN_PROC)){
            #if defined(__linux__)
                sys_proc_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(WIN32)
                sys_proc_windows(WM_SYS_LOCATION);
            #elif defined(__MACH__)
                sys_proc_mac(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.procinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Running processes inventory is not available for this OS version.");
            #endif
            #ifdef DEBUG
                print_rbtree(sys->processes_entry, sys->processes_entry_mutex);
            #endif
            sys_send_scan_event(PROC_SCAN);
        }

        mtinfo(WM_SYS_LOGTAG, "Evaluation finished.");

        if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_WRITE, &sys->state, sizeof(sys->state)) < 0)
            mterror(WM_SYS_LOGTAG, "Couldn't save running state: %s (%d)", strerror(errno), errno);

        update_next_time(&run);

        if (time_sleep = get_sleep_time(&run), time_sleep >= 0) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            w_time_delay(1000 * time_sleep);
        } else {
            mterror(WM_SYS_LOGTAG, "Interval overtaken.");
        }
    }

    return NULL;
}

time_t get_sleep_time(int *run) {
    time_t seconds_to_sleep = LONG_MAX;
    time_t time_aux = 0;
    int modules_expired = 0;

    time_t now = time(NULL);

    // Check hardware time
    if (sys->flags.hwinfo) {
        time_aux = sys->state.hw_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_HW;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_HW;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_HW;
            *run &= RUN_HW;
            seconds_to_sleep = time_aux;
        }
    }
    // Check operative system time
    if (sys->flags.osinfo) {
        time_aux = sys->state.os_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_OS;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_OS;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_OS;
            *run &= RUN_OS;
            seconds_to_sleep = time_aux;
        }
    }
    // Check interfaces time
    if (sys->flags.netinfo) {
        time_aux = sys->state.interfaces_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_IFACE;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_IFACE;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_IFACE;
            *run &= RUN_IFACE;
            seconds_to_sleep = time_aux;
        }
    }
    // Check programs/packages time
    if (sys->flags.programinfo) {
        time_aux = sys->state.programs_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_PKG;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_PKG;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_PKG;
            *run &= RUN_PKG;
            seconds_to_sleep = time_aux;
        }
    }
#ifdef WIN32
    // Check hotfixes time
    if (sys->flags.hotfixinfo) {
        time_aux = sys->state.hotfixes_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_HFIX;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_HFIX;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_HFIX;
            *run &= RUN_HFIX;
            seconds_to_sleep = time_aux;
        }
    }
#endif
    // Check ports time
    if (sys->flags.portsinfo) {
        time_aux = sys->state.ports_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_PORT;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_PORT;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_PORT;
            *run &= RUN_PORT;
            seconds_to_sleep = time_aux;
        }
    }
    // Check processes time
    if (sys->flags.procinfo) {
        time_aux = sys->state.processes_next_time - now;
        if (time_aux < 0) {
            modules_expired |= RUN_PROC;
            seconds_to_sleep = -1;
        } else if (time_aux == seconds_to_sleep) {
            *run |= RUN_PROC;
        } else if (time_aux < seconds_to_sleep) {
            *run |= RUN_PROC;
            *run &= RUN_PROC;
            seconds_to_sleep = time_aux;
        }
    }
    // Check if any module time has expired
    if (modules_expired) {
        *run |= modules_expired;
        *run &= modules_expired;
    }

    return seconds_to_sleep;
}

void update_next_time(int *run) {
    if (sys->flags.netinfo && (*run & RUN_IFACE)){
        *run &= ~RUN_IFACE;
        sys->state.interfaces_next_time += sys->interfaces_interval;
    }
    if (sys->flags.osinfo && (*run & RUN_OS)){
        *run &= ~RUN_OS;
        sys->state.os_next_time += sys->os_interval;
    }
    if (sys->flags.hwinfo && (*run & RUN_HW)){
        *run &= ~RUN_HW;
        sys->state.hw_next_time += sys->hw_interval;
    }
    if (sys->flags.programinfo && (*run & RUN_PKG)){
        *run &= ~RUN_PKG;
        sys->state.programs_next_time += sys->programs_interval;
    }
    if (sys->flags.hotfixinfo && (*run & RUN_HFIX)){
        *run &= ~RUN_HFIX;
        sys->state.hotfixes_next_time += sys->hotfixes_interval;
    }
    if (sys->flags.portsinfo && (*run & RUN_PORT)){
        *run &= ~RUN_PORT;
        sys->state.ports_next_time += sys->ports_interval;
    }
    if (sys->flags.procinfo && (*run & RUN_PROC)){
        *run &= ~RUN_PROC;
        sys->state.processes_next_time += sys->processes_interval;
    }
}

// Setup module

static void wm_sys_setup(wm_sys_t *_sys) {

    sys = _sys;
    wm_sys_check();

    // Read running state

    if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_READ, &sys->state, sizeof(sys->state)) < 0)
        memset(&sys->state, 0, sizeof(sys->state));

    #ifndef WIN32

    // Connect to socket
    queue_fd = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting
    atexit(wm_sys_cleanup);

    #endif
}

#ifndef WIN32
void wm_sys_cleanup() {
    close(queue_fd);
    mtinfo(WM_SYS_LOGTAG, "Module finished.");
}
#endif

// Check configuration

void wm_sys_check() {

    // Check if disabled

    if (!sys->flags.enabled) {
        mtinfo(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if evals

    if (!sys->flags.netinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Network scan disabled.");
    }

    if (!sys->flags.osinfo) {
        mtdebug1(WM_SYS_LOGTAG, "OS scan disabled.");
    }

    if (!sys->flags.hwinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Hardware scan disabled.");
    }

    if (!sys->flags.procinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Running processes inventory disabled.");
    }

    if (!sys->flags.programinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Installed programs scan disabled.");
    }

    if (!sys->flags.portsinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Opened ports scan disabled.");
    }

    // Check if interval

    if (!sys->default_interval) {
        sys->default_interval = WM_SYS_DEF_INTERVAL;
    }

    if (!sys->hw_interval) {
        sys->hw_interval = sys->default_interval;
    }

    if (!sys->os_interval) {
        sys->os_interval = sys->default_interval;
    }

    if (!sys->interfaces_interval) {
        sys->interfaces_interval = sys->default_interval;
    }

    if (!sys->programs_interval) {
        sys->programs_interval = sys->default_interval;
    }

    if (!sys->hotfixes_interval) {
        sys->hotfixes_interval = sys->default_interval;
    }

    if (!sys->ports_interval) {
        sys->ports_interval = sys->default_interval;
    }

    if (!sys->processes_interval) {
        sys->processes_interval = sys->default_interval;
    }
}

// Get read data

cJSON *wm_sys_dump(const wm_sys_t *sys) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sys = cJSON_CreateObject();

    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sys,"disabled","no"); else cJSON_AddStringToObject(wm_sys,"disabled","yes");
    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sys,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_sys,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_sys,"hw_interval",sys->hw_interval);
    cJSON_AddNumberToObject(wm_sys,"os_interval",sys->os_interval);
    cJSON_AddNumberToObject(wm_sys,"interfaces_interval",sys->interfaces_interval);
    cJSON_AddNumberToObject(wm_sys,"programs_interval",sys->programs_interval);
#ifdef WIN32
    cJSON_AddNumberToObject(wm_sys,"hotfixes_interval",sys->hotfixes_interval);
#endif
    cJSON_AddNumberToObject(wm_sys,"ports_interval",sys->ports_interval);
    cJSON_AddNumberToObject(wm_sys,"processes_interval",sys->processes_interval);
    if (sys->flags.netinfo) cJSON_AddStringToObject(wm_sys,"network","yes"); else cJSON_AddStringToObject(wm_sys,"network","no");
    if (sys->flags.osinfo) cJSON_AddStringToObject(wm_sys,"os","yes"); else cJSON_AddStringToObject(wm_sys,"os","no");
    if (sys->flags.hwinfo) cJSON_AddStringToObject(wm_sys,"hardware","yes"); else cJSON_AddStringToObject(wm_sys,"hardware","no");
    if (sys->flags.programinfo) cJSON_AddStringToObject(wm_sys,"packages","yes"); else cJSON_AddStringToObject(wm_sys,"packages","no");
    if (sys->flags.portsinfo) cJSON_AddStringToObject(wm_sys,"ports","yes"); else cJSON_AddStringToObject(wm_sys,"ports","no");
    if (sys->flags.allports) cJSON_AddStringToObject(wm_sys,"ports_all","yes"); else cJSON_AddStringToObject(wm_sys,"ports_all","no");
    if (sys->flags.procinfo) cJSON_AddStringToObject(wm_sys,"processes","yes"); else cJSON_AddStringToObject(wm_sys,"processes","no");
#ifdef WIN32
    if (sys->flags.hotfixinfo) cJSON_AddStringToObject(wm_sys,"hotfixes","yes"); else cJSON_AddStringToObject(wm_sys,"hotfixes","no");
#endif

    cJSON_AddItemToObject(root,"syscollector",wm_sys);

    return root;
}

void wm_sys_destroy(wm_sys_t *sys) {
    free_hw_data(sys->hw_data);
    free_os_data(sys->os_data);
    rbtree_destroy(sys->interfaces_entry);
    rbtree_destroy(sys->programs_entry);
    rbtree_destroy(sys->hotfixes_entry);
    rbtree_destroy(sys->ports_entry);
    rbtree_destroy(sys->processes_entry);

    free(sys);
}

int wm_sys_get_random_id() {
    int ID;
    char random_id[SERIAL_LENGTH];

    snprintf(random_id, SERIAL_LENGTH - 1, "%u%u", os_random(), os_random());
    ID = atoi(random_id);

    if (ID < 0) {
        ID = -ID;
    }

    return ID;
}

// Initialize syscollector datastores
void sys_initialize_datastores() {
    sys->hw_data = init_hw_data();
    sys->os_data = init_os_data();
    sys->interfaces_entry = rbtree_init();
    sys->programs_entry = rbtree_init();
    sys->hotfixes_entry = rbtree_init();
    sys->ports_entry = rbtree_init();
    sys->processes_entry = rbtree_init();

    if (!sys->hw_data || !sys->os_data || !sys->interfaces_entry || !sys->programs_entry || !sys->hotfixes_entry || !sys->ports_entry || !sys->processes_entry) {
        merror_exit("Error while creating data structures. Exiting."); // LCOV_EXCL_LINE
    }

    rbtree_set_dispose(sys->interfaces_entry, (void (*)(void *))free_interface_data);
    rbtree_set_dispose(sys->programs_entry, (void (*)(void *))free_program_data);
    rbtree_set_dispose(sys->hotfixes_entry, (void (*)(void *))free_hotfix_data);
    rbtree_set_dispose(sys->ports_entry, (void (*)(void *))free_port_data);
    rbtree_set_dispose(sys->processes_entry, (void (*)(void *))free_process_data);

    w_mutex_init(&sys->hardware_mutex, NULL);
    w_mutex_init(&sys->os_mutex, NULL);
    w_mutex_init(&sys->interfaces_entry_mutex, NULL);
    w_mutex_init(&sys->programs_entry_mutex, NULL);
    w_mutex_init(&sys->hotfixes_entry_mutex, NULL);
    w_mutex_init(&sys->ports_entry_mutex, NULL);
    w_mutex_init(&sys->processes_entry_mutex, NULL);
}

// Initialize hw_entry structure
hw_entry * init_hw_data() {
    hw_entry * hw_data = NULL;
    os_calloc(1, sizeof(hw_entry), hw_data);
    hw_data->board_serial = NULL;
    hw_data->cpu_name = NULL;
    hw_data->cpu_cores = INT_MIN;
    hw_data->cpu_MHz = 0.0;
    hw_data->ram_total = LONG_MIN;
    hw_data->ram_free = LONG_MIN;
    hw_data->ram_usage = INT_MIN;
    return hw_data;
}

// Initialize os_entry structure
os_entry * init_os_data() {
    os_entry * os_data = NULL;
    os_calloc(1, sizeof(os_entry), os_data);
    os_data->hostname = NULL;
    os_data->architecture = NULL;
    os_data->os_name = NULL;
    os_data->os_release = NULL;
    os_data->os_version = NULL;
    os_data->os_codename = NULL;
    os_data->os_major = NULL;
    os_data->os_minor = NULL;
    os_data->os_build = NULL;
    os_data->os_platform = NULL;
    os_data->sysname = NULL;
    os_data->release = NULL;
    os_data->version = NULL;
    return os_data;
}

// Initialize net_addr structure
net_addr * init_net_addr() {
    net_addr * net = NULL;
    os_calloc(1, sizeof(net_addr), net);
    net->address = NULL;
    net->netmask = NULL;
    net->broadcast = NULL;
    net->metric = INT_MIN;
    net->gateway = NULL;
    net->dhcp = NULL;
    return net;
}

// Initialize interface_entry_data structure
interface_entry_data * init_interface_data_entry() {
    interface_entry_data * data = NULL;
    os_calloc(1, sizeof(interface_entry_data), data);
    data->name = NULL;
    data->adapter = NULL;
    data->type = NULL;
    data->state = NULL;
    data->mac = NULL;
    data->mtu = INT_MIN;
    data->tx_packets = INT_MIN;
    data->rx_packets = INT_MIN;
    data->tx_bytes = INT_MIN;
    data->rx_bytes = INT_MIN;
    data->tx_errors = INT_MIN;
    data->rx_errors = INT_MIN;
    data->tx_dropped = INT_MIN;
    data->rx_dropped = INT_MIN;
    data->ipv4 = NULL;
    data->ipv6 = NULL;
    data->enabled = 0;
    return data;
}

// Initialize program_entry_data structure
program_entry_data * init_program_data_entry() {
    program_entry_data * data = NULL;
    os_calloc(1, sizeof(program_entry_data), data);
    data->format = NULL;
    data->name = NULL;
    data->priority = NULL;
    data->group = NULL;
    data->size = LONG_MIN;
    data->vendor = NULL;
    data->install_time = NULL;
    data->version = NULL;
    data->architecture = NULL;
    data->multi_arch = NULL;
    data->source = NULL;
    data->description = NULL;
    data->location = NULL;
    data->installed = 0;
    return data;
}

// Initialize hotfix_entry_data structure
hotfix_entry_data * init_hotfix_data_entry() {
    hotfix_entry_data * data = NULL;
    os_calloc(1, sizeof(hotfix_entry_data), data);
    data->hotfix = NULL;
    data->installed = 0;
    return data;
}

// Initialize port_entry_data structure
port_entry_data * init_port_data_entry() {
    port_entry_data * data = NULL;
    os_calloc(1, sizeof(port_entry_data), data);
    data->protocol = NULL;
    data->local_ip = NULL;
    data->local_port = INT_MIN;
    data->remote_ip = NULL;
    data->remote_port = INT_MIN;
    data->tx_queue = INT_MIN;
    data->rx_queue = INT_MIN;
    data->inode = INT_MIN;
    data->state = NULL;
    data->pid = INT_MIN;
    data->process = NULL;
    data->opened = 0;
    return data;
}

// Initialize process_entry_data structure
process_entry_data * init_process_data_entry() {
    process_entry_data * data = NULL;
    os_calloc(1, sizeof(process_entry_data), data);
    data->pid = INT_MIN;
    data->ppid = INT_MIN;
    data->name = NULL;
    data->cmd = NULL;
    data->argvs = NULL;
    data->state = NULL;
    data->euser = NULL;
    data->ruser = NULL;
    data->suser = NULL;
    data->egroup = NULL;
    data->rgroup = NULL;
    data->sgroup = NULL;
    data->fgroup = NULL;
    data->priority = INT_MIN;
    data->nice = INT_MIN;
    data->size = LONG_MIN;
    data->vm_size = LONG_MIN;
    data->resident = LONG_MIN;
    data->share = LONG_MIN;
    data->start_time = LLONG_MIN;
    data->utime = LLONG_MIN;
    data->stime = LLONG_MIN;
    data->pgrp = INT_MIN;
    data->session = INT_MIN;
    data->nlwp = INT_MIN;
    data->tgid = INT_MIN;
    data->tty = INT_MIN;
    data->processor = INT_MIN;
    data->running = 0;
    return data;
}

// Free hw_entry structure
void free_hw_data(hw_entry * data) {
    if (!data) {
        return;
    }
    if (data->board_serial) {
        os_free(data->board_serial);
    }
    if (data->cpu_name) {
        os_free(data->cpu_name);
    }

    os_free(data);
}

// Free os_entry structure
void free_os_data(os_entry * data) {
    if (!data) {
        return;
    }
    if (data->hostname) {
        os_free(data->hostname);
    }
    if (data->architecture) {
        os_free(data->architecture);
    }
    if (data->os_name) {
        os_free(data->os_name);
    }
    if (data->os_release) {
        os_free(data->os_release);
    }
    if (data->os_version) {
        os_free(data->os_version);
    }
    if (data->os_codename) {
        os_free(data->os_codename);
    }
    if (data->os_major) {
        os_free(data->os_major);
    }
    if (data->os_minor) {
        os_free(data->os_minor);
    }
    if (data->os_build) {
        os_free(data->os_build);
    }
    if (data->os_platform) {
        os_free(data->os_platform);
    }
    if (data->sysname) {
        os_free(data->sysname);
    }
    if (data->release) {
        os_free(data->release);
    }
    if (data->version) {
        os_free(data->version);
    }

    os_free(data);
}

// Free interface_entry_data structure
void free_interface_data(interface_entry_data * data) {
    if (!data) {
        return;
    }
    if (data->name) {
        os_free(data->name);
    }
    if (data->adapter) {
        os_free(data->adapter);
    }
    if (data->type) {
        os_free(data->type);
    }
    if (data->state) {
        os_free(data->state);
    }
    if (data->mac) {
        os_free(data->mac);
    }
    if (data->ipv4) {
        if (data->ipv4->address) {
            free_strarray(data->ipv4->address);
        }
        if (data->ipv4->netmask) {
            free_strarray(data->ipv4->netmask);
        }
        if (data->ipv4->broadcast) {
            free_strarray(data->ipv4->broadcast);
        }
        if (data->ipv4->gateway) {
            os_free(data->ipv4->gateway);
        }
        if (data->ipv4->dhcp) {
            os_free(data->ipv4->dhcp);
        }
        os_free(data->ipv4);
    }
    if (data->ipv6) {
        if (data->ipv6->address) {
            free_strarray(data->ipv6->address);
        }
        if (data->ipv6->netmask) {
            free_strarray(data->ipv6->netmask);
        }
        if (data->ipv6->broadcast) {
            free_strarray(data->ipv6->broadcast);
        }
        if (data->ipv6->gateway) {
            os_free(data->ipv6->gateway);
        }
        if (data->ipv6->dhcp) {
            os_free(data->ipv6->dhcp);
        }
        os_free(data->ipv6);
    }

    os_free(data);
}

// Free program_entry_data structure
void free_program_data(program_entry_data * data) {
    if (!data) {
        return;
    }
    if (data->format) {
        os_free(data->format);
    }
    if (data->name) {
        os_free(data->name);
    }
    if (data->priority) {
        os_free(data->priority);
    }
    if (data->group) {
        os_free(data->group);
    }
    if (data->vendor) {
        os_free(data->vendor);
    }
    if (data->install_time) {
        os_free(data->install_time);
    }
    if (data->version) {
        os_free(data->version);
    }
    if (data->architecture) {
        os_free(data->architecture);
    }
    if (data->multi_arch) {
        os_free(data->multi_arch);
    }
    if (data->source) {
        os_free(data->source);
    }
    if (data->description) {
        os_free(data->description);
    }
    if (data->location) {
        os_free(data->location);
    }

    os_free(data);
}

// Free hotfix_entry_data structure
void free_hotfix_data(hotfix_entry_data * data){
    if (!data) {
        return;
    }
    if (data->hotfix) {
        os_free(data->hotfix);
    }

    os_free(data);
}

// Free port_entry_data structure
void free_port_data(port_entry_data * data) {
    if (!data) {
        return;
    }
    if (data->protocol) {
        os_free(data->protocol);
    }
    if (data->local_ip) {
        os_free(data->local_ip);
    }
    if (data->remote_ip) {
        os_free(data->remote_ip);
    }
    if (data->state) {
        os_free(data->state);
    }
    if (data->process) {
        os_free(data->process);
    }

    os_free(data);
}

// Free process_entry_data structure
void free_process_data(process_entry_data * data) {
    if (!data) {
        return;
    }
    if (data->name) {
        os_free(data->name);
    }
    if (data->cmd) {
        os_free(data->cmd);
    }
    if (data->argvs) {
        free_strarray(data->argvs);
    }
    if (data->state) {
        os_free(data->state);
    }
    if (data->euser) {
        os_free(data->euser);
    }
    if (data->ruser) {
        os_free(data->ruser);
    }
    if (data->suser) {
        os_free(data->suser);
    }
    if (data->egroup) {
        os_free(data->egroup);
    }
    if (data->rgroup) {
        os_free(data->rgroup);
    }
    if (data->sgroup) {
        os_free(data->sgroup);
    }
    if (data->fgroup) {
        os_free(data->fgroup);
    }

    os_free(data);
}

// Analyze if update the hardware information
char * analyze_hw(hw_entry * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    char * string = NULL;
    int modify = 0;

    if (!entry_data->board_serial) {
        free_hw_data(entry_data);
        mdebug1("Couldn't get the serial number of the board");
        return NULL;
    }

    w_mutex_lock(&sys->hardware_mutex);

    modify = (sys->hw_data && sys->hw_data->board_serial);
    if (json_event = hw_json_event(modify ? sys->hw_data : NULL, entry_data, modify ? SYS_MODIFY : SYS_ADD, timestamp), json_event) {
        free_hw_data(sys->hw_data);
        sys->hw_data = entry_data;

        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }
    else {
        free_hw_data(entry_data);
    }

    w_mutex_unlock(&sys->hardware_mutex);

    return string;
}

// Analyze if update the operative system information
char * analyze_os(os_entry * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    char * string = NULL;
    int modify = 0;

    if (!entry_data->os_name) {
        free_os_data(entry_data);
        mdebug1("Couldn't get the name of the operative system");
        return NULL;
    }

    w_mutex_lock(&sys->os_mutex);

    modify = (sys->os_data && sys->os_data->os_name);
    if (json_event = os_json_event(modify ? sys->os_data : NULL, entry_data, modify ? SYS_MODIFY : SYS_ADD, timestamp), json_event) {
        free_os_data(sys->os_data);
        sys->os_data = entry_data;

        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }
    else {
        free_os_data(entry_data);
    }

    w_mutex_unlock(&sys->os_mutex);

    return string;
}

// Analyze if insert new interface or update an existing one
char * analyze_interface(interface_entry_data * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    interface_entry_data * saved_data = NULL;
    char * key = NULL;
    char * string = NULL;

    if (entry_data->name) {
        os_strdup(entry_data->name, key);
    }
    else {
        free_interface_data(entry_data);
        mdebug1("Couldn't get the name of the interface");
        return NULL;
    }

    entry_data->enabled = 1;

    w_mutex_lock(&sys->interfaces_entry_mutex);

    if (saved_data = (interface_entry_data *) rbtree_get(sys->interfaces_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->interfaces_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->interfaces_entry_mutex);
            free_interface_data(entry_data);
            mdebug1("Couldn't insert interface into hash table: '%s'", key);
            free(key);
            return NULL;
        }
        json_event = interface_json_event(NULL, entry_data, SYS_ADD, timestamp);
    }
    else {
        // Checking for changes
        saved_data->enabled = 1;
        if (json_event = interface_json_event(saved_data, entry_data, SYS_MODIFY, timestamp), json_event) {
            if (update_entry(sys->interfaces_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->interfaces_entry_mutex);
                cJSON_Delete(json_event);
                free_interface_data(entry_data);
                mdebug1("Couldn't update interface in hash table: '%s'", key);
                free(key);
                return NULL;
            }
        }
        else {
            free_interface_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->interfaces_entry_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    free(key);

    return string;
}

// Analyze if insert new program or update an existing one
char * analyze_program(program_entry_data * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    program_entry_data * saved_data = NULL;
    char * key = NULL;
    char * string = NULL;

    if (entry_data->name) {
        os_calloc(OS_SIZE_128, sizeof(char), key);
        if (entry_data->version && entry_data->architecture) {
            sprintf(key, "%s-%s-%s", entry_data->name, entry_data->version, entry_data->architecture);
        }
        else if (entry_data->version) {
            sprintf(key, "%s-%s", entry_data->name, entry_data->version);
        }
        else if (entry_data->architecture) {
            sprintf(key, "%s-%s", entry_data->name, entry_data->architecture);
        }
        else {
            sprintf(key, "%s", entry_data->name);
        }
    }
    else {
        free_program_data(entry_data);
        mdebug1("Couldn't get the name of the program");
        return NULL;
    }

    entry_data->installed = 1;

    w_mutex_lock(&sys->programs_entry_mutex);

    if (saved_data = (program_entry_data *) rbtree_get(sys->programs_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->programs_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->programs_entry_mutex);
            free_program_data(entry_data);
            mdebug1("Couldn't insert program into hash table: '%s'", key);
            free(key);
            return NULL;
        }
        json_event = program_json_event(NULL, entry_data, SYS_ADD, timestamp);
    }
    else {
        // Checking for changes
        saved_data->installed = 1;
        if (json_event = program_json_event(saved_data, entry_data, SYS_MODIFY, timestamp), json_event) {
            if (update_entry(sys->programs_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->programs_entry_mutex);
                cJSON_Delete(json_event);
                free_program_data(entry_data);
                mdebug1("Couldn't update program in hash table: '%s'", key);
                free(key);
                return NULL;
            }
        }
        else {
            free_program_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->programs_entry_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    free(key);

    return string;
}

// Analyze if insert new hotfix or update an existing one
char * analyze_hotfix(hotfix_entry_data * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    hotfix_entry_data * saved_data = NULL;
    char * key = NULL;
    char * string = NULL;

    if (entry_data->hotfix) {
        os_strdup(entry_data->hotfix, key);
    }
    else {
        free_hotfix_data(entry_data);
        mdebug1("Couldn't get the name of the hotfix");
        return NULL;
    }

    entry_data->installed = 1;

    w_mutex_lock(&sys->hotfixes_entry_mutex);

    if (saved_data = (hotfix_entry_data *) rbtree_get(sys->hotfixes_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->hotfixes_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->hotfixes_entry_mutex);
            free_hotfix_data(entry_data);
            mdebug1("Couldn't insert hotfix into hash table: '%s'", key);
            free(key);
            return NULL;
        }
        json_event = hotfix_json_event(NULL, entry_data, SYS_ADD, timestamp);
    }
    else {
        // Checking for changes
        saved_data->installed = 1;
        if (json_event = hotfix_json_event(saved_data, entry_data, SYS_MODIFY, timestamp), json_event) {
            if (update_entry(sys->hotfixes_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->hotfixes_entry_mutex);
                cJSON_Delete(json_event);
                free_hotfix_data(entry_data);
                mdebug1("Couldn't update hotfix in hash table: '%s'", key);
                free(key);
                return NULL;
            }
        }
        else {
            free_hotfix_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->hotfixes_entry_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    free(key);

    return string;
}

// Analyze if insert new port or update an existing one
char * analyze_port(port_entry_data * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    port_entry_data * saved_data = NULL;
    char * key = NULL;
    char * string = NULL;

    if (entry_data->protocol && entry_data->local_ip && entry_data->local_port > INT_MIN) {
        os_calloc(OS_SIZE_128, sizeof(char), key);
        if (entry_data->pid > INT_MIN) {
            sprintf(key, "%s-%s-%d-%d", entry_data->protocol, entry_data->local_ip, entry_data->local_port, entry_data->pid);
        }
        else {
            sprintf(key, "%s-%s-%d", entry_data->protocol, entry_data->local_ip, entry_data->local_port);
        }
    }
    else {
        free_port_data(entry_data);
        mdebug1("Couldn't get the local ip/port of the connection");
        return NULL;
    }

    entry_data->opened = 1;

    w_mutex_lock(&sys->ports_entry_mutex);

    if (saved_data = (port_entry_data *) rbtree_get(sys->ports_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->ports_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->ports_entry_mutex);
            free_port_data(entry_data);
            mdebug1("Couldn't insert port into hash table: '%s'", key);
            free(key);
            return NULL;
        }
        json_event = port_json_event(NULL, entry_data, SYS_ADD, timestamp);
    }
    else {
        // Checking for changes
        saved_data->opened = 1;
        if (json_event = port_json_event(saved_data, entry_data, SYS_MODIFY, timestamp), json_event) {
            if (update_entry(sys->ports_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->ports_entry_mutex);
                cJSON_Delete(json_event);
                free_port_data(entry_data);
                mdebug1("Couldn't update port in hash table: '%s'", key);
                free(key);
                return NULL;
            }
        }
        else {
            free_port_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->ports_entry_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    free(key);

    return string;
}

// Analyze if insert new process or update an existing one
char * analyze_process(process_entry_data * entry_data, const char * timestamp) {
    cJSON * json_event = NULL;
    process_entry_data * saved_data = NULL;
    char * key = NULL;
    char * string = NULL;

    if (entry_data->pid > INT_MIN && entry_data->name) {
        os_calloc(OS_SIZE_128, sizeof(char), key);
        sprintf(key, "%d-%s", entry_data->pid, entry_data->name);
    }
    else {
        free_process_data(entry_data);
        mdebug1("Couldn't get the pid/name of the process");
        return NULL;
    }

    entry_data->running = 1;

    w_mutex_lock(&sys->processes_entry_mutex);

    if (saved_data = (process_entry_data *) rbtree_get(sys->processes_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->processes_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->processes_entry_mutex);
            free_process_data(entry_data);
            mdebug1("Couldn't insert process into hash table: '%s'", key);
            free(key);
            return NULL;
        }
        json_event = process_json_event(NULL, entry_data, SYS_ADD, timestamp);
    }
    else {
        // Checking for changes
        saved_data->running = 1;
        if (json_event = process_json_event(saved_data, entry_data, SYS_MODIFY, timestamp), json_event) {
            if (update_entry(sys->processes_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->processes_entry_mutex);
                cJSON_Delete(json_event);
                free_process_data(entry_data);
                mdebug1("Couldn't update process in hash table: '%s'", key);
                free(key);
                return NULL;
            }
        }
        else {
            free_process_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->processes_entry_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    free(key);

    return string;
}

// Deletes the disabled interfaces from the hash table
void check_disabled_interfaces() {
    cJSON * json_event = NULL;
    char * string = NULL;
    char ** keys;
    int i;

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    w_mutex_lock(&sys->interfaces_entry_mutex);
    keys = rbtree_keys(sys->interfaces_entry);
    w_mutex_unlock(&sys->interfaces_entry_mutex);

    for (i = 0; keys[i] != NULL; i++) {

        w_mutex_lock(&sys->interfaces_entry_mutex);

        interface_entry_data * data = rbtree_get(sys->interfaces_entry, keys[i]);

        if (!data) {
            w_mutex_unlock(&sys->interfaces_entry_mutex);
            continue;
        }

        if (!data->enabled) {
            if (json_event = interface_json_event(NULL, data, SYS_DELETE, timestamp), json_event) {
                string = cJSON_PrintUnformatted(json_event);
                cJSON_Delete(json_event);
                mtdebug2(WM_SYS_LOGTAG, "check_disabled_interfaces() sending '%s'", string);
            #ifdef WIN32
                wm_sendmsg(usec, 0, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #else
                wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #endif
                free(string);
            }
            delete_entry(sys->interfaces_entry, keys[i]);
        } else {
            // We reset the enabled flag
            data->enabled = 0;
        }

        w_mutex_unlock(&sys->interfaces_entry_mutex);
    }

    free_strarray(keys);
    free(timestamp);

    return;
}

// Deletes the uninstalled programs from the hash table
void check_uninstalled_programs() {
    cJSON * json_event = NULL;
    char * string = NULL;
    char ** keys;
    int i;

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    w_mutex_lock(&sys->programs_entry_mutex);
    keys = rbtree_keys(sys->programs_entry);
    w_mutex_unlock(&sys->programs_entry_mutex);

    for (i = 0; keys[i] != NULL; i++) {

        w_mutex_lock(&sys->programs_entry_mutex);

        program_entry_data * data = rbtree_get(sys->programs_entry, keys[i]);

        if (!data) {
            w_mutex_unlock(&sys->programs_entry_mutex);
            continue;
        }

        if (!data->installed) {
            if (json_event = program_json_event(NULL, data, SYS_DELETE, timestamp), json_event) {
                string = cJSON_PrintUnformatted(json_event);
                cJSON_Delete(json_event);
                mtdebug2(WM_SYS_LOGTAG, "check_uninstalled_programs() sending '%s'", string);
            #ifdef WIN32
                wm_sendmsg(usec, 0, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #else
                wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #endif
                free(string);
            }
            delete_entry(sys->programs_entry, keys[i]);
        } else {
            // We reset the installed flag
            data->installed = 0;
        }

        w_mutex_unlock(&sys->programs_entry_mutex);
    }

    free_strarray(keys);
    free(timestamp);

    return;
}

// Deletes the uninstalled hotfixes from the hash table
void check_uninstalled_hotfixes() {
    cJSON * json_event = NULL;
    char * string = NULL;
    char ** keys;
    int i;

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    w_mutex_lock(&sys->hotfixes_entry_mutex);
    keys = rbtree_keys(sys->hotfixes_entry);
    w_mutex_unlock(&sys->hotfixes_entry_mutex);

    for (i = 0; keys[i] != NULL; i++) {

        w_mutex_lock(&sys->hotfixes_entry_mutex);

        hotfix_entry_data * data = rbtree_get(sys->hotfixes_entry, keys[i]);

        if (!data) {
            w_mutex_unlock(&sys->hotfixes_entry_mutex);
            continue;
        }

        if (!data->installed) {
            if (json_event = hotfix_json_event(NULL, data, SYS_DELETE, timestamp), json_event) {
                string = cJSON_PrintUnformatted(json_event);
                cJSON_Delete(json_event);
                mtdebug2(WM_SYS_LOGTAG, "check_uninstalled_hotfixes() sending '%s'", string);
            #ifdef WIN32
                wm_sendmsg(usec, 0, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #else
                wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #endif
                free(string);
            }
            delete_entry(sys->hotfixes_entry, keys[i]);
        } else {
            // We reset the installed flag
            data->installed = 0;
        }

        w_mutex_unlock(&sys->hotfixes_entry_mutex);
    }

    free_strarray(keys);
    free(timestamp);

    return;
}

// Deletes the closed ports from the hash table
void check_closed_ports() {
    cJSON * json_event = NULL;
    char * string = NULL;
    char ** keys;
    int i;

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    w_mutex_lock(&sys->ports_entry_mutex);
    keys = rbtree_keys(sys->ports_entry);
    w_mutex_unlock(&sys->ports_entry_mutex);

    for (i = 0; keys[i] != NULL; i++) {

        w_mutex_lock(&sys->ports_entry_mutex);

        port_entry_data * data = rbtree_get(sys->ports_entry, keys[i]);

        if (!data) {
            w_mutex_unlock(&sys->ports_entry_mutex);
            continue;
        }

        if (!data->opened) {
            if (json_event = port_json_event(NULL, data, SYS_DELETE, timestamp), json_event) {
                string = cJSON_PrintUnformatted(json_event);
                cJSON_Delete(json_event);
                mtdebug2(WM_SYS_LOGTAG, "check_closed_ports() sending '%s'", string);
            #ifdef WIN32
                wm_sendmsg(usec, 0, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #else
                wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #endif
                free(string);
            }
            delete_entry(sys->ports_entry, keys[i]);
        } else {
            // We reset the opened flag
            data->opened = 0;
        }

        w_mutex_unlock(&sys->ports_entry_mutex);
    }

    free_strarray(keys);
    free(timestamp);

    return;
}

// Deletes the terminated processes from the hash table
void check_terminated_processes() {
    cJSON * json_event = NULL;
    char * string = NULL;
    char ** keys;
    int i;

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    w_mutex_lock(&sys->processes_entry_mutex);
    keys = rbtree_keys(sys->processes_entry);
    w_mutex_unlock(&sys->processes_entry_mutex);

    for (i = 0; keys[i] != NULL; i++) {

        w_mutex_lock(&sys->processes_entry_mutex);

        process_entry_data * data = rbtree_get(sys->processes_entry, keys[i]);

        if (!data) {
            w_mutex_unlock(&sys->processes_entry_mutex);
            continue;
        }

        if (!data->running) {
            if (json_event = process_json_event(NULL, data, SYS_DELETE, timestamp), json_event) {
                string = cJSON_PrintUnformatted(json_event);
                cJSON_Delete(json_event);
                mtdebug2(WM_SYS_LOGTAG, "check_terminated_processes() sending '%s'", string);
            #ifdef WIN32
                wm_sendmsg(usec, 0, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #else
                wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
            #endif
                free(string);
            }
            delete_entry(sys->processes_entry, keys[i]);
        } else {
            // We reset the running flag
            data->running = 0;
        }

        w_mutex_unlock(&sys->processes_entry_mutex);
    }

    free_strarray(keys);
    free(timestamp);

    return;
}

// Insert entry into hash table
int insert_entry(rb_tree * tree, const char * key, void * data) {
    if (rbtree_insert(tree, key, data) == NULL) {
        mdebug1("Couldn't insert entry, duplicated key: '%s'", key);
        return -1;
    }
    return 0;
}

// Update entry to hash table
int update_entry(rb_tree * tree, const char * key, void * data) {
    if (rbtree_replace(tree, key, data) == NULL) {
        mdebug1("Unable to update entry to db, key not found: '%s'", key);
        return -1;
    }
    return 0;
}

// Delete entry from hash table
void delete_entry(rb_tree * tree, const char * key) {
    process_entry_data * data;
    if (data = rbtree_get(tree, key), data) {
        rbtree_delete(tree, key);
    }
}

// Print keys from hash table
void print_rbtree(rb_tree * tree, pthread_mutex_t mutex) {
    char **keys;
    int i = 0;

    w_mutex_lock(&mutex);
    keys = rbtree_keys(tree);
    w_mutex_unlock(&mutex);

    while(keys[i]) {
        mdebug2("entry(%d) => (%s)", i, keys[i]);
        i++;
    }
    free_strarray(keys);

    return;
}

// Send a syscollector scan event to the manager
void sys_send_scan_event(sys_scan_event type) {
    cJSON * json_event = NULL;
    char * string = NULL;
    char ** keys = NULL;
    int items = 0;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    switch (type) {
        case HW_SCAN:
        case OS_SCAN:
            items = 1;
            break;
        case IFACE_SCAN:
            w_mutex_lock(&sys->interfaces_entry_mutex);
            keys = rbtree_keys(sys->interfaces_entry);
            w_mutex_unlock(&sys->interfaces_entry_mutex);
            break;
        case PKG_SCAN:
            w_mutex_lock(&sys->programs_entry_mutex);
            keys = rbtree_keys(sys->programs_entry);
            w_mutex_unlock(&sys->programs_entry_mutex);
            break;
        case HFIX_SCAN:
            w_mutex_lock(&sys->hotfixes_entry_mutex);
            keys = rbtree_keys(sys->hotfixes_entry);
            w_mutex_unlock(&sys->hotfixes_entry_mutex);
            break;
        case PORT_SCAN:
            w_mutex_lock(&sys->ports_entry_mutex);
            keys = rbtree_keys(sys->ports_entry);
            w_mutex_unlock(&sys->ports_entry_mutex);
            break;
        case PROC_SCAN:
            w_mutex_lock(&sys->processes_entry_mutex);
            keys = rbtree_keys(sys->processes_entry);
            w_mutex_unlock(&sys->processes_entry_mutex);
            break;
        default:
            break;
    }

    if (keys) {
        for (items = 0; keys[items] != NULL; items++);
        free_strarray(keys);
    }

    if (json_event = sys_json_scan_event(type, time(NULL), items), json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
        mtdebug2(WM_SYS_LOGTAG, "sys_send_scan_event() sending '%s'", string);
    #ifdef WIN32
        wm_sendmsg(usec, 0, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
    #else
        wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
    #endif
        free(string);
    }
}

cJSON * hw_json_event(hw_entry * old_data, hw_entry * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = hw_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * hw_inventory = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "hardware");

    cJSON_AddItemToObject(object, "data", hw_inventory);
    cJSON_AddStringToObject(hw_inventory, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(hw_inventory, "timestamp", timestamp);

    cJSON_AddItemToObject(hw_inventory, "attributes", hw_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(hw_inventory, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(hw_inventory, "old_attributes", hw_json_attributes(old_data));
    }

    return object;
}

cJSON * hw_json_compare(hw_entry * old_data, hw_entry * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->board_serial && new_data->board_serial) {
        if (strcmp(old_data->board_serial, new_data->board_serial)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("board_serial"));
        }
    } else if ((!old_data->board_serial && new_data->board_serial) || (old_data->board_serial && !new_data->board_serial)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("board_serial"));
    }
    if (old_data->cpu_name && new_data->cpu_name) {
        if (strcmp(old_data->cpu_name, new_data->cpu_name)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("cpu_name"));
        }
    } else if ((!old_data->cpu_name && new_data->cpu_name) || (old_data->cpu_name && !new_data->cpu_name)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("cpu_name"));
    }
    if (old_data->cpu_cores != new_data->cpu_cores) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("cpu_cores"));
    }
    if (old_data->cpu_MHz != new_data->cpu_MHz) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("cpu_MHz"));
    }
    if (old_data->ram_total != new_data->ram_total) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ram_total"));
    }
    if (old_data->ram_free != new_data->ram_free) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ram_free"));
    }
    if (old_data->ram_usage != new_data->ram_usage) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ram_usage"));
    }
    return changed_attributes;
}

cJSON * hw_json_attributes(hw_entry * data) {
    cJSON * attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "board_serial", data->board_serial);
    if (data->cpu_name) {
        cJSON_AddStringToObject(attributes, "cpu_name", data->cpu_name);
    }
    if (data->cpu_cores > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "cpu_cores", data->cpu_cores);
    }
    if (data->cpu_MHz > 0.0) {
        cJSON_AddNumberToObject(attributes, "cpu_MHz", data->cpu_MHz);
    }
    if (data->ram_total > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "ram_total", data->ram_total);
    }
    if (data->ram_free > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "ram_free", data->ram_free);
    }
    if (data->ram_usage > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "ram_usage", data->ram_usage);
    }
    return attributes;
}

cJSON * os_json_event(os_entry * old_data, os_entry * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = os_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * os_inventory = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "OS");

    cJSON_AddItemToObject(object, "data", os_inventory);
    cJSON_AddStringToObject(os_inventory, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(os_inventory, "timestamp", timestamp);

    cJSON_AddItemToObject(os_inventory, "attributes", os_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(os_inventory, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(os_inventory, "old_attributes", os_json_attributes(old_data));
    }

    return object;
}

cJSON * os_json_compare(os_entry * old_data, os_entry * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->hostname && new_data->hostname) {
        if (strcmp(old_data->hostname, new_data->hostname)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("hostname"));
        }
    } else if ((!old_data->hostname && new_data->hostname) || (old_data->hostname && !new_data->hostname)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("hostname"));
    }
    if (old_data->architecture && new_data->architecture) {
        if (strcmp(old_data->architecture, new_data->architecture)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("architecture"));
        }
    } else if ((!old_data->architecture && new_data->architecture) || (old_data->architecture && !new_data->architecture)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("architecture"));
    }
    if (old_data->os_name && new_data->os_name) {
        if (strcmp(old_data->os_name, new_data->os_name)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_name"));
        }
    } else if ((!old_data->os_name && new_data->os_name) || (old_data->os_name && !new_data->os_name)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_name"));
    }
    if (old_data->os_release && new_data->os_release) {
        if (strcmp(old_data->os_release, new_data->os_release)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_release"));
        }
    } else if ((!old_data->os_release && new_data->os_release) || (old_data->os_release && !new_data->os_release)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_release"));
    }
    if (old_data->os_version && new_data->os_version) {
        if (strcmp(old_data->os_version, new_data->os_version)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_version"));
        }
    } else if ((!old_data->os_version && new_data->os_version) || (old_data->os_version && !new_data->os_version)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_version"));
    }
    if (old_data->os_codename && new_data->os_codename) {
        if (strcmp(old_data->os_codename, new_data->os_codename)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_codename"));
        }
    } else if ((!old_data->os_codename && new_data->os_codename) || (old_data->os_codename && !new_data->os_codename)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_codename"));
    }
    if (old_data->os_major && new_data->os_major) {
        if (strcmp(old_data->os_major, new_data->os_major)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_major"));
        }
    } else if ((!old_data->os_major && new_data->os_major) || (old_data->os_major && !new_data->os_major)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_major"));
    }
    if (old_data->os_minor && new_data->os_minor) {
        if (strcmp(old_data->os_minor, new_data->os_minor)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_minor"));
        }
    } else if ((!old_data->os_minor && new_data->os_minor) || (old_data->os_minor && !new_data->os_minor)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_minor"));
    }
    if (old_data->os_build && new_data->os_build) {
        if (strcmp(old_data->os_build, new_data->os_build)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_build"));
        }
    } else if ((!old_data->os_build && new_data->os_build) || (old_data->os_build && !new_data->os_build)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_build"));
    }
    if (old_data->os_platform && new_data->os_platform) {
        if (strcmp(old_data->os_platform, new_data->os_platform)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_platform"));
        }
    } else if ((!old_data->os_platform && new_data->os_platform) || (old_data->os_platform && !new_data->os_platform)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("os_platform"));
    }
    if (old_data->sysname && new_data->sysname) {
        if (strcmp(old_data->sysname, new_data->sysname)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sysname"));
        }
    } else if ((!old_data->sysname && new_data->sysname) || (old_data->sysname && !new_data->sysname)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sysname"));
    }
    if (old_data->release && new_data->release) {
        if (strcmp(old_data->release, new_data->release)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("release"));
        }
    } else if ((!old_data->release && new_data->release) || (old_data->release && !new_data->release)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("release"));
    }
    if (old_data->version && new_data->version) {
        if (strcmp(old_data->version, new_data->version)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("version"));
        }
    } else if ((!old_data->version && new_data->version) || (old_data->version && !new_data->version)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("version"));
    }
    return changed_attributes;
}

cJSON * os_json_attributes(os_entry * data) {
    cJSON * attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "os_name", data->os_name);
    if (data->os_major) {
        cJSON_AddStringToObject(attributes, "os_major", data->os_major);
    }
    if (data->os_minor) {
        cJSON_AddStringToObject(attributes, "os_minor", data->os_minor);
    }
    if (data->os_build) {
        cJSON_AddStringToObject(attributes, "os_build", data->os_build);
    }
    if (data->os_version) {
        cJSON_AddStringToObject(attributes, "os_version", data->os_version);
    }
    if (data->os_codename) {
        cJSON_AddStringToObject(attributes, "os_codename", data->os_codename);
    }
    if (data->os_platform) {
        cJSON_AddStringToObject(attributes, "os_platform", data->os_platform);
    }
    if (data->sysname) {
        cJSON_AddStringToObject(attributes, "sysname", data->sysname);
    }
    if (data->hostname) {
        cJSON_AddStringToObject(attributes, "hostname", data->hostname);
    }
    if (data->release) {
        cJSON_AddStringToObject(attributes, "release", data->release);
    }
    if (data->version) {
        cJSON_AddStringToObject(attributes, "version", data->version);
    }
    if (data->architecture) {
        cJSON_AddStringToObject(attributes, "architecture", data->architecture);
    }
    if (data->os_release) {
        cJSON_AddStringToObject(attributes, "os_release", data->os_release);
    }
    return attributes;
}

cJSON * interface_json_event(interface_entry_data * old_data, interface_entry_data * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = interface_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * iface = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "network");

    cJSON_AddItemToObject(object, "data", iface);
    cJSON_AddStringToObject(iface, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(iface, "timestamp", timestamp);

    cJSON_AddItemToObject(iface, "attributes", interface_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(iface, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(iface, "old_attributes", interface_json_attributes(old_data));
    }

    return object;
}

cJSON * interface_json_compare(interface_entry_data * old_data, interface_entry_data * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->name && new_data->name) {
        if (strcmp(old_data->name, new_data->name)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("name"));
        }
    } else if ((!old_data->name && new_data->name) || (old_data->name && !new_data->name)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("name"));
    }
    if (old_data->adapter && new_data->adapter) {
        if (strcmp(old_data->adapter, new_data->adapter)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("adapter"));
        }
    } else if ((!old_data->adapter && new_data->adapter) || (old_data->adapter && !new_data->adapter)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("adapter"));
    }
    if (old_data->type && new_data->type) {
        if (strcmp(old_data->type, new_data->type)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("type"));
        }
    } else if ((!old_data->type && new_data->type) || (old_data->type && !new_data->type)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("type"));
    }
    if (old_data->state && new_data->state) {
        if (strcmp(old_data->state, new_data->state)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("state"));
        }
    } else if ((!old_data->state && new_data->state) || (old_data->state && !new_data->state)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("state"));
    }
    if (old_data->mac && new_data->mac) {
        if (strcmp(old_data->mac, new_data->mac)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mac"));
        }
    } else if ((!old_data->mac && new_data->mac) || (old_data->mac && !new_data->mac)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mac"));
    }
    if (old_data->ipv4 && new_data->ipv4) {
        if (old_data->ipv4->address && new_data->ipv4->address) {
            int i;
            for (i = 0; old_data->ipv4->address[i] && new_data->ipv4->address[i]; i++) {
                if (strcmp(old_data->ipv4->address[i], new_data->ipv4->address[i])) {
                    cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_address"));
                }
            }
            if ((!old_data->ipv4->address[i] && new_data->ipv4->address[i]) || (old_data->ipv4->address[i] && !new_data->ipv4->address[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_address"));
            }
        } else if ((!old_data->ipv4->address && new_data->ipv4->address) || (old_data->ipv4->address && !new_data->ipv4->address)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_address"));
        }
        if (old_data->ipv4->netmask && new_data->ipv4->netmask) {
            int i;
            for (i = 0; old_data->ipv4->netmask[i] && new_data->ipv4->netmask[i]; i++) {
                if (strcmp(old_data->ipv4->netmask[i], new_data->ipv4->netmask[i])) {
                    cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_netmask"));
                }
            }
            if ((!old_data->ipv4->netmask[i] && new_data->ipv4->netmask[i]) || (old_data->ipv4->netmask[i] && !new_data->ipv4->netmask[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_netmask"));
            }
        } else if ((!old_data->ipv4->netmask && new_data->ipv4->netmask) || (old_data->ipv4->netmask && !new_data->ipv4->netmask)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_netmask"));
        }
        if (old_data->ipv4->broadcast && new_data->ipv4->broadcast) {
            int i;
            for (i = 0; old_data->ipv4->broadcast[i] && new_data->ipv4->broadcast[i]; i++) {
                if (strcmp(old_data->ipv4->broadcast[i], new_data->ipv4->broadcast[i])) {
                    cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_broadcast"));
                }
            }
            if ((!old_data->ipv4->broadcast[i] && new_data->ipv4->broadcast[i]) || (old_data->ipv4->broadcast[i] && !new_data->ipv4->broadcast[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_broadcast"));
            }
        } else if ((!old_data->ipv4->broadcast && new_data->ipv4->broadcast) || (old_data->ipv4->broadcast && !new_data->ipv4->broadcast)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_broadcast"));
        }
        if (old_data->ipv4->gateway && new_data->ipv4->gateway) {
            if (strcmp(old_data->ipv4->gateway, new_data->ipv4->gateway)) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_gateway"));
            }
        } else if ((!old_data->ipv4->gateway && new_data->ipv4->gateway) || (old_data->ipv4->gateway && !new_data->ipv4->gateway)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_gateway"));
        }
        if (old_data->ipv4->dhcp && new_data->ipv4->dhcp) {
            if (strcmp(old_data->ipv4->dhcp, new_data->ipv4->dhcp)) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_dhcp"));
            }
        } else if ((!old_data->ipv4->dhcp && new_data->ipv4->dhcp) || (old_data->ipv4->dhcp && !new_data->ipv4->dhcp)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_dhcp"));
        }
        if (old_data->ipv4->metric != new_data->ipv4->metric) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4_metric"));
        }
    } else if ((!old_data->ipv4 && new_data->ipv4) || (old_data->ipv4 && !new_data->ipv4)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv4"));
    }
    if (old_data->ipv6 && new_data->ipv6) {
        if (old_data->ipv6->address && new_data->ipv6->address) {
            int i;
            for (i = 0; old_data->ipv6->address[i] && new_data->ipv6->address[i]; i++) {
                if (strcmp(old_data->ipv6->address[i], new_data->ipv6->address[i])) {
                    cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_address"));
                }
            }
            if ((!old_data->ipv6->address[i] && new_data->ipv6->address[i]) || (old_data->ipv6->address[i] && !new_data->ipv6->address[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_address"));
            }
        } else if ((!old_data->ipv6->address && new_data->ipv6->address) || (old_data->ipv6->address && !new_data->ipv6->address)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_address"));
        }
        if (old_data->ipv6->netmask && new_data->ipv6->netmask) {
            int i;
            for (i = 0; old_data->ipv6->netmask[i] && new_data->ipv6->netmask[i]; i++) {
                if (strcmp(old_data->ipv6->netmask[i], new_data->ipv6->netmask[i])) {
                    cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_netmask"));
                }
            }
            if ((!old_data->ipv6->netmask[i] && new_data->ipv6->netmask[i]) || (old_data->ipv6->netmask[i] && !new_data->ipv6->netmask[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_netmask"));
            }
        } else if ((!old_data->ipv6->netmask && new_data->ipv6->netmask) || (old_data->ipv6->netmask && !new_data->ipv6->netmask)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_netmask"));
        }
        if (old_data->ipv6->broadcast && new_data->ipv6->broadcast) {
            int i;
            for (i = 0; old_data->ipv6->broadcast[i] && new_data->ipv6->broadcast[i]; i++) {
                if (strcmp(old_data->ipv6->broadcast[i], new_data->ipv6->broadcast[i])) {
                    cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_broadcast"));
                }
            }
            if ((!old_data->ipv6->broadcast[i] && new_data->ipv6->broadcast[i]) || (old_data->ipv6->broadcast[i] && !new_data->ipv6->broadcast[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_broadcast"));
            }
        } else if ((!old_data->ipv6->broadcast && new_data->ipv6->broadcast) || (old_data->ipv6->broadcast && !new_data->ipv6->broadcast)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_broadcast"));
        }
        if (old_data->ipv6->gateway && new_data->ipv6->gateway) {
            if (strcmp(old_data->ipv6->gateway, new_data->ipv6->gateway)) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_gateway"));
            }
        } else if ((!old_data->ipv6->gateway && new_data->ipv6->gateway) || (old_data->ipv6->gateway && !new_data->ipv6->gateway)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_gateway"));
        }
        if (old_data->ipv6->dhcp && new_data->ipv6->dhcp) {
            if (strcmp(old_data->ipv6->dhcp, new_data->ipv6->dhcp)) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_dhcp"));
            }
        } else if ((!old_data->ipv6->dhcp && new_data->ipv6->dhcp) || (old_data->ipv6->dhcp && !new_data->ipv6->dhcp)) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_dhcp"));
        }
        if (old_data->ipv6->metric != new_data->ipv6->metric) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6_metric"));
        }
    } else if ((!old_data->ipv6 && new_data->ipv6) || (old_data->ipv6 && !new_data->ipv6)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ipv6"));
    }
    if (old_data->mtu != new_data->mtu) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtu"));
    }
    if (old_data->tx_packets != new_data->tx_packets) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tx_packets"));
    }
    if (old_data->rx_packets != new_data->rx_packets) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rx_packets"));
    }
    if (old_data->tx_bytes != new_data->tx_bytes) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tx_bytes"));
    }
    if (old_data->rx_bytes != new_data->rx_bytes) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rx_bytes"));
    }
    if (old_data->tx_errors != new_data->tx_errors) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tx_errors"));
    }
    if (old_data->rx_errors != new_data->rx_errors) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rx_errors"));
    }
    if (old_data->tx_dropped != new_data->tx_dropped) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tx_dropped"));
    }
    if (old_data->rx_dropped != new_data->rx_dropped) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rx_dropped"));
    }
    return changed_attributes;
}

cJSON * interface_json_attributes(interface_entry_data * data) {
    cJSON * attributes = cJSON_CreateObject();
    int i = 0;

    cJSON_AddStringToObject(attributes, "name", data->name);
    if (data->adapter) {
        cJSON_AddStringToObject(attributes, "adapter", data->adapter);
    }
    if (data->type) {
        cJSON_AddStringToObject(attributes, "type", data->type);
    }
    if (data->state) {
        cJSON_AddStringToObject(attributes, "state", data->state);
    }
    if (data->mac) {
        cJSON_AddStringToObject(attributes, "MAC", data->mac);
    }
    if (data->mtu > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "MTU", data->mtu);
    }
    if (data->tx_packets > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tx_packets", data->tx_packets);
    }
    if (data->rx_packets > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "rx_packets", data->rx_packets);
    }
    if (data->tx_bytes > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tx_bytes", data->tx_bytes);
    }
    if (data->rx_bytes > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "rx_bytes", data->rx_bytes);
    }
    if (data->tx_errors > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tx_errors", data->tx_errors);
    }
    if (data->rx_errors > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "rx_errors", data->rx_errors);
    }
    if (data->tx_dropped > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tx_dropped", data->tx_dropped);
    }
    if (data->rx_dropped > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "rx_dropped", data->rx_dropped);
    }
    if (data->ipv4 && data->ipv4->address) {
        cJSON *ipv4 = cJSON_CreateObject();
        cJSON *ipv4_addr = cJSON_CreateArray();
        for (i = 0; data->ipv4->address[i]; i++) {
            if (strlen(data->ipv4->address[i])) {
                cJSON_AddItemToArray(ipv4_addr, cJSON_CreateString(data->ipv4->address[i]));
            }
        }
        if (cJSON_GetArraySize(ipv4_addr) > 0) {
            cJSON_AddItemToObject(ipv4, "address", ipv4_addr);
            if (data->ipv4->netmask) {
                cJSON *ipv4_netmask = cJSON_CreateArray();
                for (i = 0; data->ipv4->netmask[i]; i++) {
                    if (strlen(data->ipv4->netmask[i])) {
                        cJSON_AddItemToArray(ipv4_netmask, cJSON_CreateString(data->ipv4->netmask[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv4_netmask) > 0) {
                    cJSON_AddItemToObject(ipv4, "netmask", ipv4_netmask);
                } else {
                    cJSON_Delete(ipv4_netmask);
                }
            }
            if (data->ipv4->broadcast) {
                cJSON *ipv4_broadcast = cJSON_CreateArray();
                for (i = 0; data->ipv4->broadcast[i]; i++) {
                    if (strlen(data->ipv4->broadcast[i])) {
                        cJSON_AddItemToArray(ipv4_broadcast, cJSON_CreateString(data->ipv4->broadcast[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv4_broadcast) > 0) {
                    cJSON_AddItemToObject(ipv4, "broadcast", ipv4_broadcast);
                } else {
                    cJSON_Delete(ipv4_broadcast);
                }
            }
            if (data->ipv4->metric > INT_MIN) {
                cJSON_AddNumberToObject(ipv4, "metric", data->ipv4->metric);
            }
            if (data->ipv4->gateway) {
                cJSON_AddStringToObject(ipv4, "gateway", data->ipv4->gateway);
            }
            if (data->ipv4->dhcp) {
                cJSON_AddStringToObject(ipv4, "DHCP", data->ipv4->dhcp);
            }
            cJSON_AddItemToObject(attributes, "IPv4", ipv4);
        } else {
            cJSON_Delete(ipv4_addr);
            cJSON_Delete(ipv4);
        }
    }
    if (data->ipv6 && data->ipv6->address) {
        cJSON *ipv6 = cJSON_CreateObject();
        cJSON *ipv6_addr = cJSON_CreateArray();
        for (i = 0; data->ipv6->address[i]; i++) {
            if (strlen(data->ipv6->address[i])) {
                cJSON_AddItemToArray(ipv6_addr, cJSON_CreateString(data->ipv6->address[i]));
            }
        }
        if (cJSON_GetArraySize(ipv6_addr) > 0) {
            cJSON_AddItemToObject(ipv6, "address", ipv6_addr);
            if (data->ipv6->netmask) {
                cJSON *ipv6_netmask = cJSON_CreateArray();
                for (i = 0; data->ipv6->netmask[i]; i++) {
                    if (strlen(data->ipv6->netmask[i])) {
                        cJSON_AddItemToArray(ipv6_netmask, cJSON_CreateString(data->ipv6->netmask[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv6_netmask) > 0) {
                    cJSON_AddItemToObject(ipv6, "netmask", ipv6_netmask);
                } else {
                    cJSON_Delete(ipv6_netmask);
                }
            }
            if (data->ipv6->broadcast) {
                cJSON *ipv6_broadcast = cJSON_CreateArray();
                for (i = 0; data->ipv6->broadcast[i]; i++) {
                    if (strlen(data->ipv6->broadcast[i])) {
                        cJSON_AddItemToArray(ipv6_broadcast, cJSON_CreateString(data->ipv6->broadcast[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv6_broadcast) > 0) {
                    cJSON_AddItemToObject(ipv6, "broadcast", ipv6_broadcast);
                } else {
                    cJSON_Delete(ipv6_broadcast);
                }
            }
            if (data->ipv6->metric > INT_MIN) {
                cJSON_AddNumberToObject(ipv6, "metric", data->ipv6->metric);
            }
            if (data->ipv6->gateway) {
                cJSON_AddStringToObject(ipv6, "gateway", data->ipv6->gateway);
            }
            if (data->ipv6->dhcp) {
                cJSON_AddStringToObject(ipv6, "DHCP", data->ipv6->dhcp);
            }
            cJSON_AddItemToObject(attributes, "IPv6", ipv6);
        } else {
            cJSON_Delete(ipv6_addr);
            cJSON_Delete(ipv6);
        }
    }
    return attributes;
}

cJSON * program_json_event(program_entry_data * old_data, program_entry_data * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = program_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * program = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "program");

    cJSON_AddItemToObject(object, "data", program);
    cJSON_AddStringToObject(program, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(program, "timestamp", timestamp);

    cJSON_AddItemToObject(program, "attributes", program_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(program, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(program, "old_attributes", program_json_attributes(old_data));
    }

    return object;
}

cJSON * program_json_compare(program_entry_data * old_data, program_entry_data * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->format && new_data->format) {
        if (strcmp(old_data->format, new_data->format)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("format"));
        }
    } else if ((!old_data->format && new_data->format) || (old_data->format && !new_data->format)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("format"));
    }
    if (old_data->name && new_data->name) {
        if (strcmp(old_data->name, new_data->name)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("name"));
        }
    } else if ((!old_data->name && new_data->name) || (old_data->name && !new_data->name)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("name"));
    }
    if (old_data->priority && new_data->priority) {
        if (strcmp(old_data->priority, new_data->priority)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("priority"));
        }
    } else if ((!old_data->priority && new_data->priority) || (old_data->priority && !new_data->priority)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("priority"));
    }
    if (old_data->group && new_data->group) {
        if (strcmp(old_data->group, new_data->group)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group"));
        }
    } else if ((!old_data->group && new_data->group) || (old_data->group && !new_data->group)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group"));
    }
    if (old_data->vendor && new_data->vendor) {
        if (strcmp(old_data->vendor, new_data->vendor)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("vendor"));
        }
    } else if ((!old_data->vendor && new_data->vendor) || (old_data->vendor && !new_data->vendor)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("vendor"));
    }
    if (old_data->install_time && new_data->install_time) {
        if (strcmp(old_data->install_time, new_data->install_time)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("install_time"));
        }
    } else if ((!old_data->install_time && new_data->install_time) || (old_data->install_time && !new_data->install_time)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("install_time"));
    }
    if (old_data->version && new_data->version) {
        if (strcmp(old_data->version, new_data->version)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("version"));
        }
    } else if ((!old_data->version && new_data->version) || (old_data->version && !new_data->version)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("version"));
    }
    if (old_data->architecture && new_data->architecture) {
        if (strcmp(old_data->architecture, new_data->architecture)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("architecture"));
        }
    } else if ((!old_data->architecture && new_data->architecture) || (old_data->architecture && !new_data->architecture)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("architecture"));
    }
    if (old_data->multi_arch && new_data->multi_arch) {
        if (strcmp(old_data->multi_arch, new_data->multi_arch)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("multi_arch"));
        }
    } else if ((!old_data->multi_arch && new_data->multi_arch) || (old_data->multi_arch && !new_data->multi_arch)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("multi_arch"));
    }
    if (old_data->source && new_data->source) {
        if (strcmp(old_data->source, new_data->source)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("source"));
        }
    } else if ((!old_data->source && new_data->source) || (old_data->source && !new_data->source)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("source"));
    }
    if (old_data->description && new_data->description) {
        if (strcmp(old_data->description, new_data->description)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("description"));
        }
    } else if ((!old_data->description && new_data->description) || (old_data->description && !new_data->description)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("description"));
    }
    if (old_data->location && new_data->location) {
        if (strcmp(old_data->location, new_data->location)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("location"));
        }
    } else if ((!old_data->location && new_data->location) || (old_data->location && !new_data->location)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("location"));
    }
    if (old_data->size != new_data->size) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
    }
    return changed_attributes;
}

cJSON * program_json_attributes(program_entry_data * data) {
    cJSON * attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "name", data->name);
    if (data->format) {
        cJSON_AddStringToObject(attributes, "format", data->format);
    }
    if (data->priority) {
        cJSON_AddStringToObject(attributes, "priority", data->priority);
    }
    if (data->group) {
        cJSON_AddStringToObject(attributes, "group", data->group);
    }
    if (data->size > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "size", data->size);
    }
    if (data->vendor) {
        cJSON_AddStringToObject(attributes, "vendor", data->vendor);
    }
    if (data->install_time) {
        cJSON_AddStringToObject(attributes, "install_time", data->install_time);
    }
    if (data->version) {
        cJSON_AddStringToObject(attributes, "version", data->version);
    }
    if (data->architecture) {
        cJSON_AddStringToObject(attributes, "architecture", data->architecture);
    }
    if (data->multi_arch) {
        cJSON_AddStringToObject(attributes, "multi-arch", data->multi_arch);
    }
    if (data->source) {
        cJSON_AddStringToObject(attributes, "source", data->source);
    }
    if (data->description) {
        cJSON_AddStringToObject(attributes, "description", data->description);
    }
    if (data->location) {
        cJSON_AddStringToObject(attributes, "location", data->location);
    }
    return attributes;
}

cJSON * hotfix_json_event(hotfix_entry_data * old_data, hotfix_entry_data * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = hotfix_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * hfix = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "hotfix");

    cJSON_AddItemToObject(object, "data", hfix);
    cJSON_AddStringToObject(hfix, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(hfix, "timestamp", timestamp);

    cJSON_AddItemToObject(hfix, "attributes", hotfix_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(hfix, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(hfix, "old_attributes", hotfix_json_attributes(old_data));
    }

    return object;
}

cJSON * hotfix_json_compare(hotfix_entry_data * old_data, hotfix_entry_data * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->hotfix && new_data->hotfix) {
        if (strcmp(old_data->hotfix, new_data->hotfix)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("hotfix"));
        }
    } else if ((!old_data->hotfix && new_data->hotfix) || (old_data->hotfix && !new_data->hotfix)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("hotfix"));
    }
    return changed_attributes;
}

cJSON * hotfix_json_attributes(hotfix_entry_data * data) {
    cJSON * attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "hotfix", data->hotfix);
    return attributes;
}

cJSON * port_json_event(port_entry_data * old_data, port_entry_data * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = port_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * port = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "port");

    cJSON_AddItemToObject(object, "data", port);
    cJSON_AddStringToObject(port, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(port, "timestamp", timestamp);

    cJSON_AddItemToObject(port, "attributes", port_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(port, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(port, "old_attributes", port_json_attributes(old_data));
    }

    return object;
}

cJSON * port_json_compare(port_entry_data * old_data, port_entry_data * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->protocol && new_data->protocol) {
        if (strcmp(old_data->protocol, new_data->protocol)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("protocol"));
        }
    } else if ((!old_data->protocol && new_data->protocol) || (old_data->protocol && !new_data->protocol)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("protocol"));
    }
    if (old_data->local_ip && new_data->local_ip) {
        if (strcmp(old_data->local_ip, new_data->local_ip)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("local_ip"));
        }
    } else if ((!old_data->local_ip && new_data->local_ip) || (old_data->local_ip && !new_data->local_ip)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("local_ip"));
    }
    if (old_data->remote_ip && new_data->remote_ip) {
        if (strcmp(old_data->remote_ip, new_data->remote_ip)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("remote_ip"));
        }
    } else if ((!old_data->remote_ip && new_data->remote_ip) || (old_data->remote_ip && !new_data->remote_ip)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("remote_ip"));
    }
    if (old_data->state && new_data->state) {
        if (strcmp(old_data->state, new_data->state)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("state"));
        }
    } else if ((!old_data->state && new_data->state) || (old_data->state && !new_data->state)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("state"));
    }
    if (old_data->process && new_data->process) {
        if (strcmp(old_data->process, new_data->process)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("process"));
        }
    } else if ((!old_data->process && new_data->process) || (old_data->process && !new_data->process)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("process"));
    }
    if (old_data->local_port != new_data->local_port) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("local_port"));
    }
    if (old_data->remote_port != new_data->remote_port) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("remote_port"));
    }
    if (old_data->tx_queue != new_data->tx_queue) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tx_queue"));
    }
    if (old_data->rx_queue != new_data->rx_queue) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rx_queue"));
    }
    if (old_data->inode != new_data->inode) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("inode"));
    }
    if (old_data->pid != new_data->pid) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("pid"));
    }
    return changed_attributes;
}

cJSON * port_json_attributes(port_entry_data * data) {
    cJSON * attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "protocol", data->protocol);
    cJSON_AddStringToObject(attributes, "local_ip", data->local_ip);
    cJSON_AddNumberToObject(attributes, "local_port", data->local_port);
    if (data->remote_ip) {
        cJSON_AddStringToObject(attributes, "remote_ip", data->remote_ip);
    }
    if (data->remote_port > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "remote_port", data->remote_port);
    }
    if (data->tx_queue > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tx_queue", data->tx_queue);
    }
    if (data->rx_queue > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "rx_queue", data->rx_queue);
    }
    if (data->inode > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "inode", data->inode);
    }
    if (data->state) {
        cJSON_AddStringToObject(attributes, "state", data->state);
    }
    if (data->pid > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "PID", data->pid);
    }
    if (data->process) {
        cJSON_AddStringToObject(attributes, "process", data->process);
    }
    return attributes;
}

cJSON * process_json_event(process_entry_data * old_data, process_entry_data * new_data, sys_event_type type, const char * timestamp) {
    cJSON * changed_attributes = NULL;

    if (old_data) {
        changed_attributes = process_json_compare(old_data, new_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * object = cJSON_CreateObject();
    cJSON * process = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "process");

    cJSON_AddItemToObject(object, "data", process);
    cJSON_AddStringToObject(process, "type", SYS_EVENT_TYPE[type]);
    cJSON_AddStringToObject(process, "timestamp", timestamp);

    cJSON_AddItemToObject(process, "attributes", process_json_attributes(new_data));

    if (old_data) {
        cJSON_AddItemToObject(process, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(process, "old_attributes", process_json_attributes(old_data));
    }

    return object;
}

cJSON * process_json_compare(process_entry_data * old_data, process_entry_data * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if (old_data->name && new_data->name) {
        if (strcmp(old_data->name, new_data->name)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("name"));
        }
    } else if ((!old_data->name && new_data->name) || (old_data->name && !new_data->name)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("name"));
    }
    if (old_data->cmd && new_data->cmd) {
        if (strcmp(old_data->cmd, new_data->cmd)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("cmd"));
        }
    } else if ((!old_data->cmd && new_data->cmd) || (old_data->cmd && !new_data->cmd)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("cmd"));
    }
    if (old_data->argvs && new_data->argvs) {
        int i;
        for (i = 0; old_data->argvs[i] && new_data->argvs[i]; i++) {
            if (strcmp(old_data->argvs[i], new_data->argvs[i])) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("argvs"));
            }
        }
        if ((!old_data->argvs[i] && new_data->argvs[i]) || (old_data->argvs[i] && !new_data->argvs[i])) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("argvs"));
        }
    } else if ((!old_data->argvs && new_data->argvs) || (old_data->argvs && !new_data->argvs)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("argvs"));
    }
    if (old_data->state && new_data->state) {
        if (strcmp(old_data->state, new_data->state)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("state"));
        }
    } else if ((!old_data->state && new_data->state) || (old_data->state && !new_data->state)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("state"));
    }
    if (old_data->euser && new_data->euser) {
        if (strcmp(old_data->euser, new_data->euser)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("euser"));
        }
    } else if ((!old_data->euser && new_data->euser) || (old_data->euser && !new_data->euser)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("euser"));
    }
    if (old_data->ruser && new_data->ruser) {
        if (strcmp(old_data->ruser, new_data->ruser)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ruser"));
        }
    } else if ((!old_data->ruser && new_data->ruser) || (old_data->ruser && !new_data->ruser)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ruser"));
    }
    if (old_data->suser && new_data->suser) {
        if (strcmp(old_data->suser, new_data->suser)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("suser"));
        }
    } else if ((!old_data->suser && new_data->suser) || (old_data->suser && !new_data->suser)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("suser"));
    }
    if (old_data->egroup && new_data->egroup) {
        if (strcmp(old_data->egroup, new_data->egroup)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("egroup"));
        }
    } else if ((!old_data->egroup && new_data->egroup) || (old_data->egroup && !new_data->egroup)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("egroup"));
    }
    if (old_data->rgroup && new_data->rgroup) {
        if (strcmp(old_data->rgroup, new_data->rgroup)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rgroup"));
        }
    } else if ((!old_data->rgroup && new_data->rgroup) || (old_data->rgroup && !new_data->rgroup)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("rgroup"));
    }
    if (old_data->sgroup && new_data->sgroup) {
        if (strcmp(old_data->sgroup, new_data->sgroup)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sgroup"));
        }
    } else if ((!old_data->sgroup && new_data->sgroup) || (old_data->sgroup && !new_data->sgroup)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sgroup"));
    }
    if (old_data->fgroup && new_data->fgroup) {
        if (strcmp(old_data->fgroup, new_data->fgroup)) {
           cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("fgroup"));
        }
    } else if ((!old_data->fgroup && new_data->fgroup) || (old_data->fgroup && !new_data->fgroup)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("fgroup"));
    }
    if (old_data->pid != new_data->pid) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("pid"));
    }
    if (old_data->ppid != new_data->ppid) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("ppid"));
    }
    if (old_data->priority != new_data->priority) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("priority"));
    }
    if (old_data->nice != new_data->nice) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("nice"));
    }
    if (old_data->size != new_data->size) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
    }
    if (old_data->vm_size != new_data->vm_size) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("vm_size"));
    }
    if (old_data->resident != new_data->resident) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("resident"));
    }
    if (old_data->share != new_data->share) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("share"));
    }
    if (old_data->start_time != new_data->start_time) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("start_time"));
    }
    if (old_data->utime != new_data->utime) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("utime"));
    }
    if (old_data->stime != new_data->stime) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("stime"));
    }
    if (old_data->pgrp != new_data->pgrp) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("pgrp"));
    }
    if (old_data->session != new_data->session) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("session"));
    }
    if (old_data->nlwp != new_data->nlwp) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("nlwp"));
    }
    if (old_data->tgid != new_data->tgid) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tgid"));
    }
    if (old_data->tty != new_data->tty) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("tty"));
    }
    if (old_data->processor != new_data->processor) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("processor"));
    }
    return changed_attributes;
}

cJSON * process_json_attributes(process_entry_data * data) {
    cJSON * attributes = cJSON_CreateObject();
    int i = 0;

    cJSON_AddNumberToObject(attributes, "pid", data->pid);
    cJSON_AddStringToObject(attributes, "name", data->name);
    if (data->state) {
        cJSON_AddStringToObject(attributes, "state", data->state);
    }
    if (data->ppid > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "ppid", data->ppid);
    }
    if (data->utime > LLONG_MIN) {
        cJSON_AddNumberToObject(attributes, "utime", data->utime);
    }
    if (data->stime > LLONG_MIN) {
        cJSON_AddNumberToObject(attributes, "stime", data->stime);
    }
    if (data->cmd) {
        cJSON_AddStringToObject(attributes, "cmd", data->cmd);
        if (data->argvs)
        {
            cJSON *argvs = cJSON_CreateArray();
            for (i = 0; data->argvs[i]; i++) {
                if (strlen(data->argvs[i])) {
                    cJSON_AddItemToArray(argvs, cJSON_CreateString(data->argvs[i]));
                }
            }
            if (cJSON_GetArraySize(argvs) > 0) {
                cJSON_AddItemToObject(attributes, "argvs", argvs);
            } else {
                cJSON_Delete(argvs);
            }
        }
    }
    if (data->euser) {
        cJSON_AddStringToObject(attributes, "euser", data->euser);
    }
    if (data->ruser) {
        cJSON_AddStringToObject(attributes, "ruser", data->ruser);
    }
    if (data->suser) {
        cJSON_AddStringToObject(attributes, "suser", data->suser);
    }
    if (data->egroup) {
        cJSON_AddStringToObject(attributes, "egroup", data->egroup);
    }
    if (data->rgroup) {
        cJSON_AddStringToObject(attributes, "rgroup", data->rgroup);
    }
    if (data->sgroup) {
        cJSON_AddStringToObject(attributes, "sgroup", data->sgroup);
    }
    if (data->fgroup) {
        cJSON_AddStringToObject(attributes, "fgroup", data->fgroup);
    }
    if (data->priority > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "priority", data->priority);
    }
    if (data->nice > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "nice", data->nice);
    }
    if (data->size > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "size", data->size);
    }
    if (data->vm_size > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "vm_size", data->vm_size);
    }
    if (data->resident > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "resident", data->resident);
    }
    if (data->share > LONG_MIN) {
        cJSON_AddNumberToObject(attributes, "share", data->share);
    }
    if (data->start_time > LLONG_MIN) {
        cJSON_AddNumberToObject(attributes, "start_time", data->start_time);
    }
    if (data->pgrp > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "pgrp", data->pgrp);
    }
    if (data->session > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "session", data->session);
    }
    if (data->nlwp > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "nlwp", data->nlwp);
    }
    if (data->tgid > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tgid", data->tgid);
    }
    if (data->tty > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "tty", data->tty);
    }
    if (data->processor > INT_MIN) {
        cJSON_AddNumberToObject(attributes, "processor", data->processor);
    }
    return attributes;
}

cJSON * sys_json_scan_event(sys_scan_event type, time_t timestamp, int items) {
    cJSON * object = cJSON_CreateObject();
    cJSON * scan = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", SYS_SCAN_EVENT[type]);
    cJSON_AddItemToObject(object, "data", scan);
    cJSON_AddNumberToObject(scan, "timestamp", timestamp);
    cJSON_AddNumberToObject(scan, "items", items);

    return object;
}

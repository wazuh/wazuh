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

#include "syscollector.h"
#include <errno.h>

#define RUN_HW        000000001
#define RUN_OS        000000002
#define RUN_IFACE     000000004
#define RUN_PKG       000000010
#define RUN_HFIX      000000020
#define RUN_PORT      000000040
#define RUN_PROC      000000100

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
            wm_delay(1000 * time_sleep);
        } else {
            // Wait for Wazuh DB start
            wm_delay(1000);
        }
    } else {
        // Wait for Wazuh DB start
        wm_delay(1000);
        run |= (RUN_HW | RUN_OS | RUN_IFACE | RUN_PKG | RUN_HFIX | RUN_PORT | RUN_PROC);
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
            run &= ~RUN_IFACE;
            sys->state.interfaces_next_time += sys->interfaces_interval;
        }

        /* Operating System inventory */
        if (sys->flags.osinfo && (run & RUN_OS)){
            #ifdef WIN32
                sys_os_windows(WM_SYS_LOCATION);
            #else
                sys_os_unix(queue_fd, WM_SYS_LOCATION);
            #endif
            run &= ~RUN_OS;
            sys->state.os_next_time += sys->os_interval;
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
            run &= ~RUN_HW;
            sys->state.hw_next_time += sys->hw_interval;
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
            run &= ~RUN_PKG;
            sys->state.programs_next_time += sys->programs_interval;
        }

        /* Installed hotfixes inventory */
        if (sys->flags.hotfixinfo && (run & RUN_HFIX)) {
            #ifdef WIN32
                sys_hotfixes(WM_SYS_LOCATION);
            #endif
            #ifdef DEBUG
                print_rbtree(sys->hotfixes_entry, sys->hotfixes_entry_mutex);
            #endif
            run &= ~RUN_HFIX;
            sys->state.hotfixes_next_time += sys->hotfixes_interval;
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
            run &= ~RUN_PORT;
            sys->state.ports_next_time += sys->ports_interval;
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
            run &= ~RUN_PROC;
            sys->state.processes_next_time += sys->processes_interval;
        }

        mtinfo(WM_SYS_LOGTAG, "Evaluation finished.");

        if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_WRITE, &sys->state, sizeof(sys->state)) < 0)
            mterror(WM_SYS_LOGTAG, "Couldn't save running state: %s (%d)", strerror(errno), errno);

        if (time_sleep = get_sleep_time(&run), time_sleep >= 0) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            wm_delay(1000 * time_sleep);
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
    // Check operative system time
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
    // Check interfaces time
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
    // Check programs/packages time
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
#ifdef WIN32
    // Check hotfixes time
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
#endif
    // Check ports time
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
    // Check processes time
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
    // Check if any module time has expired
    if (modules_expired) {
        *run |= modules_expired;
        *run &= modules_expired;
    }

    return seconds_to_sleep;
}

// Setup module

static void wm_sys_setup(wm_sys_t *_sys) {

    sys = _sys;
    wm_sys_check();

    // Read running state

    if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_READ, &sys->state, sizeof(sys->state)) < 0)
        memset(&sys->state, 0, sizeof(sys->state));

    #ifndef WIN32

    int i;
    // Connect to socket
    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        wm_delay(1000 * WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
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

    if (!sys->default_interval)
        sys->default_interval = WM_SYS_DEF_INTERVAL;

    if (!sys->hw_interval)
        sys->hw_interval = sys->default_interval;

    if (!sys->os_interval)
        sys->os_interval = sys->default_interval;

    if (!sys->interfaces_interval)
        sys->interfaces_interval = sys->default_interval;

    if (!sys->programs_interval)
        sys->programs_interval = sys->default_interval;

    if (!sys->hotfixes_interval)
        sys->hotfixes_interval = sys->default_interval;

    if (!sys->ports_interval)
        sys->ports_interval = sys->default_interval;

    if (!sys->processes_interval)
        sys->processes_interval = sys->default_interval;
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

// Compare two hardware structures
int compare_hw(hw_entry * old_data, hw_entry * new_data) {
    if (old_data->board_serial && new_data->board_serial) {
        if (strcmp(old_data->board_serial, new_data->board_serial)) {
           return 0;
        }
    } else if ((!old_data->board_serial && new_data->board_serial) || (old_data->board_serial && !new_data->board_serial)) {
        return 0;
    }
    if (old_data->cpu_name && new_data->cpu_name) {
        if (strcmp(old_data->cpu_name, new_data->cpu_name)) {
           return 0;
        }
    } else if ((!old_data->cpu_name && new_data->cpu_name) || (old_data->cpu_name && !new_data->cpu_name)) {
        return 0;
    }
    return (old_data->cpu_cores == new_data->cpu_cores &&
            old_data->cpu_MHz == new_data->cpu_MHz &&
            old_data->ram_total == new_data->ram_total &&
            old_data->ram_free == new_data->ram_free &&
            old_data->ram_usage == new_data->ram_usage);
}

// Compare two operative system structures
int compare_os(os_entry * old_data, os_entry * new_data) {
    if (old_data->hostname && new_data->hostname) {
        if (strcmp(old_data->hostname, new_data->hostname)) {
           return 0;
        }
    } else if ((!old_data->hostname && new_data->hostname) || (old_data->hostname && !new_data->hostname)) {
        return 0;
    }
    if (old_data->architecture && new_data->architecture) {
        if (strcmp(old_data->architecture, new_data->architecture)) {
           return 0;
        }
    } else if ((!old_data->architecture && new_data->architecture) || (old_data->architecture && !new_data->architecture)) {
        return 0;
    }
    if (old_data->os_name && new_data->os_name) {
        if (strcmp(old_data->os_name, new_data->os_name)) {
           return 0;
        }
    } else if ((!old_data->os_name && new_data->os_name) || (old_data->os_name && !new_data->os_name)) {
        return 0;
    }
    if (old_data->os_release && new_data->os_release) {
        if (strcmp(old_data->os_release, new_data->os_release)) {
           return 0;
        }
    } else if ((!old_data->os_release && new_data->os_release) || (old_data->os_release && !new_data->os_release)) {
        return 0;
    }
    if (old_data->os_version && new_data->os_version) {
        if (strcmp(old_data->os_version, new_data->os_version)) {
           return 0;
        }
    } else if ((!old_data->os_version && new_data->os_version) || (old_data->os_version && !new_data->os_version)) {
        return 0;
    }
    if (old_data->os_codename && new_data->os_codename) {
        if (strcmp(old_data->os_codename, new_data->os_codename)) {
           return 0;
        }
    } else if ((!old_data->os_codename && new_data->os_codename) || (old_data->os_codename && !new_data->os_codename)) {
        return 0;
    }
    if (old_data->os_major && new_data->os_major) {
        if (strcmp(old_data->os_major, new_data->os_major)) {
           return 0;
        }
    } else if ((!old_data->os_major && new_data->os_major) || (old_data->os_major && !new_data->os_major)) {
        return 0;
    }
    if (old_data->os_minor && new_data->os_minor) {
        if (strcmp(old_data->os_minor, new_data->os_minor)) {
           return 0;
        }
    } else if ((!old_data->os_minor && new_data->os_minor) || (old_data->os_minor && !new_data->os_minor)) {
        return 0;
    }
    if (old_data->os_build && new_data->os_build) {
        if (strcmp(old_data->os_build, new_data->os_build)) {
           return 0;
        }
    } else if ((!old_data->os_build && new_data->os_build) || (old_data->os_build && !new_data->os_build)) {
        return 0;
    }
    if (old_data->os_platform && new_data->os_platform) {
        if (strcmp(old_data->os_platform, new_data->os_platform)) {
           return 0;
        }
    } else if ((!old_data->os_platform && new_data->os_platform) || (old_data->os_platform && !new_data->os_platform)) {
        return 0;
    }
    if (old_data->sysname && new_data->sysname) {
        if (strcmp(old_data->sysname, new_data->sysname)) {
           return 0;
        }
    } else if ((!old_data->sysname && new_data->sysname) || (old_data->sysname && !new_data->sysname)) {
        return 0;
    }
    if (old_data->release && new_data->release) {
        if (strcmp(old_data->release, new_data->release)) {
           return 0;
        }
    } else if ((!old_data->release && new_data->release) || (old_data->release && !new_data->release)) {
        return 0;
    }
    if (old_data->version && new_data->version) {
        if (strcmp(old_data->version, new_data->version)) {
           return 0;
        }
    } else if ((!old_data->version && new_data->version) || (old_data->version && !new_data->version)) {
        return 0;
    }
    return 1;
}

// Compare two interface structures
int compare_interface(interface_entry_data * old_data, interface_entry_data * new_data) {
    if (old_data->name && new_data->name) {
        if (strcmp(old_data->name, new_data->name)) {
           return 0;
        }
    } else if ((!old_data->name && new_data->name) || (old_data->name && !new_data->name)) {
        return 0;
    }
    if (old_data->adapter && new_data->adapter) {
        if (strcmp(old_data->adapter, new_data->adapter)) {
           return 0;
        }
    } else if ((!old_data->adapter && new_data->adapter) || (old_data->adapter && !new_data->adapter)) {
        return 0;
    }
    if (old_data->type && new_data->type) {
        if (strcmp(old_data->type, new_data->type)) {
           return 0;
        }
    } else if ((!old_data->type && new_data->type) || (old_data->type && !new_data->type)) {
        return 0;
    }
    if (old_data->state && new_data->state) {
        if (strcmp(old_data->state, new_data->state)) {
           return 0;
        }
    } else if ((!old_data->state && new_data->state) || (old_data->state && !new_data->state)) {
        return 0;
    }
    if (old_data->mac && new_data->mac) {
        if (strcmp(old_data->mac, new_data->mac)) {
           return 0;
        }
    } else if ((!old_data->mac && new_data->mac) || (old_data->mac && !new_data->mac)) {
        return 0;
    }
    if (old_data->ipv4 && new_data->ipv4) {
        if (old_data->ipv4->address && new_data->ipv4->address) {
            int i;
            for (i = 0; old_data->ipv4->address[i] && new_data->ipv4->address[i]; i++) {
                if (strcmp(old_data->ipv4->address[i], new_data->ipv4->address[i])) {
                    return 0;
                }
            }
            if ((!old_data->ipv4->address[i] && new_data->ipv4->address[i]) || (old_data->ipv4->address[i] && !new_data->ipv4->address[i])) {
                return 0;
            }
        } else if ((!old_data->ipv4->address && new_data->ipv4->address) || (old_data->ipv4->address && !new_data->ipv4->address)) {
            return 0;
        }
        if (old_data->ipv4->netmask && new_data->ipv4->netmask) {
            int i;
            for (i = 0; old_data->ipv4->netmask[i] && new_data->ipv4->netmask[i]; i++) {
                if (strcmp(old_data->ipv4->netmask[i], new_data->ipv4->netmask[i])) {
                    return 0;
                }
            }
            if ((!old_data->ipv4->netmask[i] && new_data->ipv4->netmask[i]) || (old_data->ipv4->netmask[i] && !new_data->ipv4->netmask[i])) {
                return 0;
            }
        } else if ((!old_data->ipv4->netmask && new_data->ipv4->netmask) || (old_data->ipv4->netmask && !new_data->ipv4->netmask)) {
            return 0;
        }
        if (old_data->ipv4->broadcast && new_data->ipv4->broadcast) {
            int i;
            for (i = 0; old_data->ipv4->broadcast[i] && new_data->ipv4->broadcast[i]; i++) {
                if (strcmp(old_data->ipv4->broadcast[i], new_data->ipv4->broadcast[i])) {
                    return 0;
                }
            }
            if ((!old_data->ipv4->broadcast[i] && new_data->ipv4->broadcast[i]) || (old_data->ipv4->broadcast[i] && !new_data->ipv4->broadcast[i])) {
                return 0;
            }
        } else if ((!old_data->ipv4->broadcast && new_data->ipv4->broadcast) || (old_data->ipv4->broadcast && !new_data->ipv4->broadcast)) {
            return 0;
        }
        if (old_data->ipv4->metric != new_data->ipv4->metric) {
            return 0;
        }
        if (old_data->ipv4->gateway && new_data->ipv4->gateway) {
            if (strcmp(old_data->ipv4->gateway, new_data->ipv4->gateway)) {
                return 0;
            }
        } else if ((!old_data->ipv4->gateway && new_data->ipv4->gateway) || (old_data->ipv4->gateway && !new_data->ipv4->gateway)) {
            return 0;
        }
        if (old_data->ipv4->dhcp && new_data->ipv4->dhcp) {
            if (strcmp(old_data->ipv4->dhcp, new_data->ipv4->dhcp)) {
                return 0;
            }
        } else if ((!old_data->ipv4->dhcp && new_data->ipv4->dhcp) || (old_data->ipv4->dhcp && !new_data->ipv4->dhcp)) {
            return 0;
        }
    } else if ((!old_data->ipv4 && new_data->ipv4) || (old_data->ipv4 && !new_data->ipv4)) {
        return 0;
    }
    if (old_data->ipv6 && new_data->ipv6) {
        if (old_data->ipv6->address && new_data->ipv6->address) {
            int i;
            for (i = 0; old_data->ipv6->address[i] && new_data->ipv6->address[i]; i++) {
                if (strcmp(old_data->ipv6->address[i], new_data->ipv6->address[i])) {
                    return 0;
                }
            }
            if ((!old_data->ipv6->address[i] && new_data->ipv6->address[i]) || (old_data->ipv6->address[i] && !new_data->ipv6->address[i])) {
                return 0;
            }
        } else if ((!old_data->ipv6->address && new_data->ipv6->address) || (old_data->ipv6->address && !new_data->ipv6->address)) {
            return 0;
        }
        if (old_data->ipv6->netmask && new_data->ipv6->netmask) {
            int i;
            for (i = 0; old_data->ipv6->netmask[i] && new_data->ipv6->netmask[i]; i++) {
                if (strcmp(old_data->ipv6->netmask[i], new_data->ipv6->netmask[i])) {
                    return 0;
                }
            }
            if ((!old_data->ipv6->netmask[i] && new_data->ipv6->netmask[i]) || (old_data->ipv6->netmask[i] && !new_data->ipv6->netmask[i])) {
                return 0;
            }
        } else if ((!old_data->ipv6->netmask && new_data->ipv6->netmask) || (old_data->ipv6->netmask && !new_data->ipv6->netmask)) {
            return 0;
        }
        if (old_data->ipv6->broadcast && new_data->ipv6->broadcast) {
            int i;
            for (i = 0; old_data->ipv6->broadcast[i] && new_data->ipv6->broadcast[i]; i++) {
                if (strcmp(old_data->ipv6->broadcast[i], new_data->ipv6->broadcast[i])) {
                    return 0;
                }
            }
            if ((!old_data->ipv6->broadcast[i] && new_data->ipv6->broadcast[i]) || (old_data->ipv6->broadcast[i] && !new_data->ipv6->broadcast[i])) {
                return 0;
            }
        } else if ((!old_data->ipv6->broadcast && new_data->ipv6->broadcast) || (old_data->ipv6->broadcast && !new_data->ipv6->broadcast)) {
            return 0;
        }
        if (old_data->ipv6->metric != new_data->ipv6->metric) {
            return 0;
        }
        if (old_data->ipv6->gateway && new_data->ipv6->gateway) {
            if (strcmp(old_data->ipv6->gateway, new_data->ipv6->gateway)) {
                return 0;
            }
        } else if ((!old_data->ipv6->gateway && new_data->ipv6->gateway) || (old_data->ipv6->gateway && !new_data->ipv6->gateway)) {
            return 0;
        }
        if (old_data->ipv6->dhcp && new_data->ipv6->dhcp) {
            if (strcmp(old_data->ipv6->dhcp, new_data->ipv6->dhcp)) {
                return 0;
            }
        } else if ((!old_data->ipv6->dhcp && new_data->ipv6->dhcp) || (old_data->ipv6->dhcp && !new_data->ipv6->dhcp)) {
            return 0;
        }
    } else if ((!old_data->ipv6 && new_data->ipv6) || (old_data->ipv6 && !new_data->ipv6)) {
        return 0;
    }
    return (old_data->mtu == new_data->mtu &&
            old_data->tx_packets == new_data->tx_packets &&
            old_data->rx_packets == new_data->rx_packets &&
            old_data->tx_bytes == new_data->tx_bytes &&
            old_data->rx_bytes == new_data->rx_bytes &&
            old_data->tx_errors == new_data->tx_errors &&
            old_data->rx_errors == new_data->rx_errors &&
            old_data->tx_dropped == new_data->tx_dropped &&
            old_data->rx_dropped == new_data->rx_dropped);
}

// Compare two program structures
int compare_program(program_entry_data * old_data, program_entry_data * new_data) {
    if (old_data->format && new_data->format) {
        if (strcmp(old_data->format, new_data->format)) {
           return 0;
        }
    } else if ((!old_data->format && new_data->format) || (old_data->format && !new_data->format)) {
        return 0;
    }
    if (old_data->name && new_data->name) {
        if (strcmp(old_data->name, new_data->name)) {
           return 0;
        }
    } else if ((!old_data->name && new_data->name) || (old_data->name && !new_data->name)) {
        return 0;
    }
    if (old_data->priority && new_data->priority) {
        if (strcmp(old_data->priority, new_data->priority)) {
           return 0;
        }
    } else if ((!old_data->priority && new_data->priority) || (old_data->priority && !new_data->priority)) {
        return 0;
    }
    if (old_data->group && new_data->group) {
        if (strcmp(old_data->group, new_data->group)) {
           return 0;
        }
    } else if ((!old_data->group && new_data->group) || (old_data->group && !new_data->group)) {
        return 0;
    }
    if (old_data->vendor && new_data->vendor) {
        if (strcmp(old_data->vendor, new_data->vendor)) {
           return 0;
        }
    } else if ((!old_data->vendor && new_data->vendor) || (old_data->vendor && !new_data->vendor)) {
        return 0;
    }
    if (old_data->install_time && new_data->install_time) {
        if (strcmp(old_data->install_time, new_data->install_time)) {
           return 0;
        }
    } else if ((!old_data->install_time && new_data->install_time) || (old_data->install_time && !new_data->install_time)) {
        return 0;
    }
    if (old_data->version && new_data->version) {
        if (strcmp(old_data->version, new_data->version)) {
           return 0;
        }
    } else if ((!old_data->version && new_data->version) || (old_data->version && !new_data->version)) {
        return 0;
    }
    if (old_data->architecture && new_data->architecture) {
        if (strcmp(old_data->architecture, new_data->architecture)) {
           return 0;
        }
    } else if ((!old_data->architecture && new_data->architecture) || (old_data->architecture && !new_data->architecture)) {
        return 0;
    }
    if (old_data->multi_arch && new_data->multi_arch) {
        if (strcmp(old_data->multi_arch, new_data->multi_arch)) {
           return 0;
        }
    } else if ((!old_data->multi_arch && new_data->multi_arch) || (old_data->multi_arch && !new_data->multi_arch)) {
        return 0;
    }
    if (old_data->source && new_data->source) {
        if (strcmp(old_data->source, new_data->source)) {
           return 0;
        }
    } else if ((!old_data->source && new_data->source) || (old_data->source && !new_data->source)) {
        return 0;
    }
    if (old_data->description && new_data->description) {
        if (strcmp(old_data->description, new_data->description)) {
           return 0;
        }
    } else if ((!old_data->description && new_data->description) || (old_data->description && !new_data->description)) {
        return 0;
    }
    if (old_data->location && new_data->location) {
        if (strcmp(old_data->location, new_data->location)) {
           return 0;
        }
    } else if ((!old_data->location && new_data->location) || (old_data->location && !new_data->location)) {
        return 0;
    }
    return (old_data->size == new_data->size);
}

// Compare two hotfix structures
int compare_hotfix(hotfix_entry_data * old_data, hotfix_entry_data * new_data) {
    if (old_data->hotfix && new_data->hotfix) {
        if (strcmp(old_data->hotfix, new_data->hotfix)) {
           return 0;
        }
    } else if ((!old_data->hotfix && new_data->hotfix) || (old_data->hotfix && !new_data->hotfix)) {
        return 0;
    }
    return 1;
}

// Compare two port structures
int compare_port(port_entry_data * old_data, port_entry_data * new_data) {
    if (old_data->protocol && new_data->protocol) {
        if (strcmp(old_data->protocol, new_data->protocol)) {
           return 0;
        }
    } else if ((!old_data->protocol && new_data->protocol) || (old_data->protocol && !new_data->protocol)) {
        return 0;
    }
    if (old_data->local_ip && new_data->local_ip) {
        if (strcmp(old_data->local_ip, new_data->local_ip)) {
           return 0;
        }
    } else if ((!old_data->local_ip && new_data->local_ip) || (old_data->local_ip && !new_data->local_ip)) {
        return 0;
    }
    if (old_data->remote_ip && new_data->remote_ip) {
        if (strcmp(old_data->remote_ip, new_data->remote_ip)) {
           return 0;
        }
    } else if ((!old_data->remote_ip && new_data->remote_ip) || (old_data->remote_ip && !new_data->remote_ip)) {
        return 0;
    }
    if (old_data->state && new_data->state) {
        if (strcmp(old_data->state, new_data->state)) {
           return 0;
        }
    } else if ((!old_data->state && new_data->state) || (old_data->state && !new_data->state)) {
        return 0;
    }
    if (old_data->process && new_data->process) {
        if (strcmp(old_data->process, new_data->process)) {
           return 0;
        }
    } else if ((!old_data->process && new_data->process) || (old_data->process && !new_data->process)) {
        return 0;
    }
    return (old_data->local_port == new_data->local_port &&
            old_data->remote_port == new_data->remote_port &&
            old_data->tx_queue == new_data->tx_queue &&
            old_data->rx_queue == new_data->rx_queue &&
            old_data->inode == new_data->inode &&
            old_data->pid == new_data->pid);
}

// Compare two process structures
int compare_process(process_entry_data * old_data, process_entry_data * new_data) {
    if (old_data->name && new_data->name) {
        if (strcmp(old_data->name, new_data->name)) {
           return 0;
        }
    } else if ((!old_data->name && new_data->name) || (old_data->name && !new_data->name)) {
        return 0;
    }
    if (old_data->cmd && new_data->cmd) {
        if (strcmp(old_data->cmd, new_data->cmd)) {
           return 0;
        }
    } else if ((!old_data->cmd && new_data->cmd) || (old_data->cmd && !new_data->cmd)) {
        return 0;
    }
    if (old_data->argvs && new_data->argvs) {
        int i;
        for (i = 0; old_data->argvs[i] && new_data->argvs[i]; i++) {
            if (strcmp(old_data->argvs[i], new_data->argvs[i])) {
                return 0;
            }
        }
        if ((!old_data->argvs[i] && new_data->argvs[i]) || (old_data->argvs[i] && !new_data->argvs[i])) {
            return 0;
        }
    } else if ((!old_data->argvs && new_data->argvs) || (old_data->argvs && !new_data->argvs)) {
        return 0;
    }
    if (old_data->state && new_data->state) {
        if (strcmp(old_data->state, new_data->state)) {
           return 0;
        }
    } else if ((!old_data->state && new_data->state) || (old_data->state && !new_data->state)) {
        return 0;
    }
    if (old_data->euser && new_data->euser) {
        if (strcmp(old_data->euser, new_data->euser)) {
           return 0;
        }
    } else if ((!old_data->euser && new_data->euser) || (old_data->euser && !new_data->euser)) {
        return 0;
    }
    if (old_data->ruser && new_data->ruser) {
        if (strcmp(old_data->ruser, new_data->ruser)) {
           return 0;
        }
    } else if ((!old_data->ruser && new_data->ruser) || (old_data->ruser && !new_data->ruser)) {
        return 0;
    }
    if (old_data->suser && new_data->suser) {
        if (strcmp(old_data->suser, new_data->suser)) {
           return 0;
        }
    } else if ((!old_data->suser && new_data->suser) || (old_data->suser && !new_data->suser)) {
        return 0;
    }
    if (old_data->egroup && new_data->egroup) {
        if (strcmp(old_data->egroup, new_data->egroup)) {
           return 0;
        }
    } else if ((!old_data->egroup && new_data->egroup) || (old_data->egroup && !new_data->egroup)) {
        return 0;
    }
    if (old_data->rgroup && new_data->rgroup) {
        if (strcmp(old_data->rgroup, new_data->rgroup)) {
           return 0;
        }
    } else if ((!old_data->rgroup && new_data->rgroup) || (old_data->rgroup && !new_data->rgroup)) {
        return 0;
    }
    if (old_data->sgroup && new_data->sgroup) {
        if (strcmp(old_data->sgroup, new_data->sgroup)) {
           return 0;
        }
    } else if ((!old_data->sgroup && new_data->sgroup) || (old_data->sgroup && !new_data->sgroup)) {
        return 0;
    }
    if (old_data->fgroup && new_data->fgroup) {
        if (strcmp(old_data->fgroup, new_data->fgroup)) {
           return 0;
        }
    } else if ((!old_data->fgroup && new_data->fgroup) || (old_data->fgroup && !new_data->fgroup)) {
        return 0;
    }
    return (old_data->pid == new_data->pid &&
            old_data->ppid == new_data->ppid &&
            old_data->priority == new_data->priority &&
            old_data->nice == new_data->nice &&
            old_data->size == new_data->size &&
            old_data->vm_size == new_data->vm_size &&
            old_data->resident == new_data->resident &&
            old_data->share == new_data->share &&
            old_data->start_time == new_data->start_time &&
            old_data->utime == new_data->utime &&
            old_data->stime == new_data->stime &&
            old_data->pgrp == new_data->pgrp &&
            old_data->session == new_data->session &&
            old_data->nlwp == new_data->nlwp &&
            old_data->tgid == new_data->tgid &&
            old_data->tty == new_data->tty &&
            old_data->processor == new_data->processor);
}

// Analyze if update the hardware information
char * analyze_hw(hw_entry * entry_data, int random_id, const char * timestamp) {
    cJSON * json_event = NULL;
    char * string = NULL;

    if (!entry_data->board_serial) {
        free_hw_data(entry_data);
        mdebug1("Couldn't get the serial number of the board");
        return NULL;
    }

    w_mutex_lock(&sys->hardware_mutex);

    if (!compare_hw(sys->hw_data, entry_data)) {
        free_hw_data(sys->hw_data);
        sys->hw_data = entry_data;

        json_event = hw_json_event(entry_data, random_id, timestamp);
    }
    else {
        free_hw_data(entry_data);
    }

    w_mutex_unlock(&sys->hardware_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    return string;
}

// Analyze if update the operative system information
char * analyze_os(os_entry * entry_data, int random_id, const char * timestamp) {
    cJSON * json_event = NULL;
    char * string = NULL;

    if (!entry_data->os_name) {
        free_os_data(entry_data);
        mdebug1("Couldn't get the name of the operative system");
        return NULL;
    }

    w_mutex_lock(&sys->os_mutex);

    if (!compare_os(sys->os_data, entry_data)) {
        free_os_data(sys->os_data);
        sys->os_data = entry_data;

        json_event = os_json_event(entry_data, random_id, timestamp);
    }
    else {
        free_os_data(entry_data);
    }

    w_mutex_unlock(&sys->os_mutex);

    if (json_event) {
        string = cJSON_PrintUnformatted(json_event);
        cJSON_Delete(json_event);
    }

    return string;
}

// Analyze if insert new interface or update an existing one
char * analyze_interface(interface_entry_data * entry_data, int random_id, const char * timestamp) {
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
        json_event = interface_json_event(entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->enabled = 1;
        if (!compare_interface(saved_data, entry_data)) {
            if (update_entry(sys->interfaces_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->interfaces_entry_mutex);
                free_interface_data(entry_data);
                mdebug1("Couldn't update interface in hash table: '%s'", key);
                free(key);
                return NULL;
            }
            json_event = interface_json_event(entry_data, random_id, timestamp);
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
char * analyze_program(program_entry_data * entry_data, int random_id, const char * timestamp) {
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
        json_event = program_json_event(entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->installed = 1;
        if (!compare_program(saved_data, entry_data)) {
            if (update_entry(sys->programs_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->programs_entry_mutex);
                free_program_data(entry_data);
                mdebug1("Couldn't update program in hash table: '%s'", key);
                free(key);
                return NULL;
            }
            json_event = program_json_event(entry_data, random_id, timestamp);
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
char * analyze_hotfix(hotfix_entry_data * entry_data, int random_id, const char * timestamp) {
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
        json_event = hotfix_json_event(entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->installed = 1;
        if (!compare_hotfix(saved_data, entry_data)) {
            if (update_entry(sys->hotfixes_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->hotfixes_entry_mutex);
                free_hotfix_data(entry_data);
                mdebug1("Couldn't update hotfix in hash table: '%s'", key);
                free(key);
                return NULL;
            }
            json_event = hotfix_json_event(entry_data, random_id, timestamp);
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
char * analyze_port(port_entry_data * entry_data, int random_id, const char * timestamp) {
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
        json_event = port_json_event(entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->opened = 1;
        if (!compare_port(saved_data, entry_data)) {
            if (update_entry(sys->ports_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->ports_entry_mutex);
                free_port_data(entry_data);
                mdebug1("Couldn't update port in hash table: '%s'", key);
                free(key);
                return NULL;
            }
            json_event = port_json_event(entry_data, random_id, timestamp);
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
char * analyze_process(process_entry_data * entry_data, int random_id, const char * timestamp) {
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
        json_event = process_json_event(entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->running = 1;
        if (!compare_process(saved_data, entry_data)) {
            if (update_entry(sys->processes_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->processes_entry_mutex);
                free_process_data(entry_data);
                mdebug1("Couldn't update process in hash table: '%s'", key);
                free(key);
                return NULL;
            }
            json_event = process_json_event(entry_data, random_id, timestamp);
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
    char ** keys;
    int i;

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
            delete_entry(sys->interfaces_entry, keys[i]);
        } else {
            // We reset the enabled flag
            data->enabled = 0;
        }

        w_mutex_unlock(&sys->interfaces_entry_mutex);
    }

    free_strarray(keys);

    return;
}

// Deletes the uninstalled programs from the hash table
void check_uninstalled_programs() {
    char ** keys;
    int i;

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
            delete_entry(sys->programs_entry, keys[i]);
        } else {
            // We reset the installed flag
            data->installed = 0;
        }

        w_mutex_unlock(&sys->programs_entry_mutex);
    }

    free_strarray(keys);

    return;
}

// Deletes the uninstalled hotfixes from the hash table
void check_uninstalled_hotfixes() {
    char ** keys;
    int i;

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
            delete_entry(sys->hotfixes_entry, keys[i]);
        } else {
            // We reset the installed flag
            data->installed = 0;
        }

        w_mutex_unlock(&sys->hotfixes_entry_mutex);
    }

    free_strarray(keys);

    return;
}

// Deletes the closed ports from the hash table
void check_closed_ports() {
    char ** keys;
    int i;

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
            delete_entry(sys->ports_entry, keys[i]);
        } else {
            // We reset the opened flag
            data->opened = 0;
        }

        w_mutex_unlock(&sys->ports_entry_mutex);
    }

    free_strarray(keys);

    return;
}

// Deletes the terminated processes from the hash table
void check_terminated_processes() {
    char ** keys;
    int i;

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
            delete_entry(sys->processes_entry, keys[i]);
        } else {
            // We reset the running flag
            data->running = 0;
        }

        w_mutex_unlock(&sys->processes_entry_mutex);
    }

    free_strarray(keys);

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

//
cJSON * hw_json_event(hw_entry * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *hw_inventory = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "hardware");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "inventory", hw_inventory);

    cJSON_AddStringToObject(hw_inventory, "board_serial", new_data->board_serial);
    if (new_data->cpu_name) {
        cJSON_AddStringToObject(hw_inventory, "cpu_name", new_data->cpu_name);
    }
    if (new_data->cpu_cores > INT_MIN) {
        cJSON_AddNumberToObject(hw_inventory, "cpu_cores", new_data->cpu_cores);
    }
    if (new_data->cpu_MHz > 0.0) {
        cJSON_AddNumberToObject(hw_inventory, "cpu_MHz", new_data->cpu_MHz);
    }
    if (new_data->ram_total > LONG_MIN) {
        cJSON_AddNumberToObject(hw_inventory, "ram_total", new_data->ram_total);
    }
    if (new_data->ram_free > LONG_MIN) {
        cJSON_AddNumberToObject(hw_inventory, "ram_free", new_data->ram_free);
    }
    if (new_data->ram_usage > INT_MIN) {
        cJSON_AddNumberToObject(hw_inventory, "ram_usage", new_data->ram_usage);
    }

    return object;
}

//
cJSON * os_json_event(os_entry * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *os_inventory = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "OS");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "inventory", os_inventory);

    cJSON_AddStringToObject(os_inventory, "os_name", new_data->os_name);
    if (new_data->os_major) {
        cJSON_AddStringToObject(os_inventory, "os_major", new_data->os_major);
    }
    if (new_data->os_minor) {
        cJSON_AddStringToObject(os_inventory, "os_minor", new_data->os_minor);
    }
    if (new_data->os_build) {
        cJSON_AddStringToObject(os_inventory, "os_build", new_data->os_build);
    }
    if (new_data->os_version) {
        cJSON_AddStringToObject(os_inventory, "os_version", new_data->os_version);
    }
    if (new_data->os_codename) {
        cJSON_AddStringToObject(os_inventory, "os_codename", new_data->os_codename);
    }
    if (new_data->os_platform) {
        cJSON_AddStringToObject(os_inventory, "os_platform", new_data->os_platform);
    }
    if (new_data->sysname) {
        cJSON_AddStringToObject(os_inventory, "sysname", new_data->sysname);
    }
    if (new_data->hostname) {
        cJSON_AddStringToObject(os_inventory, "hostname", new_data->hostname);
    }
    if (new_data->release) {
        cJSON_AddStringToObject(os_inventory, "release", new_data->release);
    }
    if (new_data->version) {
        cJSON_AddStringToObject(os_inventory, "version", new_data->version);
    }
    if (new_data->architecture) {
        cJSON_AddStringToObject(os_inventory, "architecture", new_data->architecture);
    }
    if (new_data->os_release) {
        cJSON_AddStringToObject(os_inventory, "os_release", new_data->os_release);
    }

    return object;
}

//
cJSON * interface_json_event(interface_entry_data * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *iface = cJSON_CreateObject();
    int i = 0;

    cJSON_AddStringToObject(object, "type", "network");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "iface", iface);

    cJSON_AddStringToObject(iface, "name", new_data->name);
    if (new_data->adapter) {
        cJSON_AddStringToObject(iface, "adapter", new_data->adapter);
    }
    if (new_data->type) {
        cJSON_AddStringToObject(iface, "type", new_data->type);
    }
    if (new_data->state) {
        cJSON_AddStringToObject(iface, "state", new_data->state);
    }
    if (new_data->mac) {
        cJSON_AddStringToObject(iface, "MAC", new_data->mac);
    }
    if (new_data->mtu > INT_MIN) {
        cJSON_AddNumberToObject(iface, "MTU", new_data->mtu);
    }
    if (new_data->tx_packets > INT_MIN) {
        cJSON_AddNumberToObject(iface, "tx_packets", new_data->tx_packets);
    }
    if (new_data->rx_packets > INT_MIN) {
        cJSON_AddNumberToObject(iface, "rx_packets", new_data->rx_packets);
    }
    if (new_data->tx_bytes > INT_MIN) {
        cJSON_AddNumberToObject(iface, "tx_bytes", new_data->tx_bytes);
    }
    if (new_data->rx_bytes > INT_MIN) {
        cJSON_AddNumberToObject(iface, "rx_bytes", new_data->rx_bytes);
    }
    if (new_data->tx_errors > INT_MIN) {
        cJSON_AddNumberToObject(iface, "tx_errors", new_data->tx_errors);
    }
    if (new_data->rx_errors > INT_MIN) {
        cJSON_AddNumberToObject(iface, "rx_errors", new_data->rx_errors);
    }
    if (new_data->tx_dropped > INT_MIN) {
        cJSON_AddNumberToObject(iface, "tx_dropped", new_data->tx_dropped);
    }
    if (new_data->rx_dropped > INT_MIN) {
        cJSON_AddNumberToObject(iface, "rx_dropped", new_data->rx_dropped);
    }
    if (new_data->ipv4 && new_data->ipv4->address) {
        cJSON *ipv4 = cJSON_CreateObject();
        cJSON *ipv4_addr = cJSON_CreateArray();
        for (i = 0; new_data->ipv4->address[i]; i++) {
            if (strlen(new_data->ipv4->address[i])) {
                cJSON_AddItemToArray(ipv4_addr, cJSON_CreateString(new_data->ipv4->address[i]));
            }
        }
        if (cJSON_GetArraySize(ipv4_addr) > 0) {
            cJSON_AddItemToObject(ipv4, "address", ipv4_addr);
            if (new_data->ipv4->netmask) {
                cJSON *ipv4_netmask = cJSON_CreateArray();
                for (i = 0; new_data->ipv4->netmask[i]; i++) {
                    if (strlen(new_data->ipv4->netmask[i])) {
                        cJSON_AddItemToArray(ipv4_netmask, cJSON_CreateString(new_data->ipv4->netmask[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv4_netmask) > 0) {
                    cJSON_AddItemToObject(ipv4, "netmask", ipv4_netmask);
                } else {
                    cJSON_Delete(ipv4_netmask);
                }
            }
            if (new_data->ipv4->broadcast) {
                cJSON *ipv4_broadcast = cJSON_CreateArray();
                for (i = 0; new_data->ipv4->broadcast[i]; i++) {
                    if (strlen(new_data->ipv4->broadcast[i])) {
                        cJSON_AddItemToArray(ipv4_broadcast, cJSON_CreateString(new_data->ipv4->broadcast[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv4_broadcast) > 0) {
                    cJSON_AddItemToObject(ipv4, "broadcast", ipv4_broadcast);
                } else {
                    cJSON_Delete(ipv4_broadcast);
                }
            }
            if (new_data->ipv4->metric > INT_MIN) {
                cJSON_AddNumberToObject(ipv4, "metric", new_data->ipv4->metric);
            }
            if (new_data->ipv4->gateway) {
                cJSON_AddStringToObject(ipv4, "gateway", new_data->ipv4->gateway);
            }
            if (new_data->ipv4->dhcp) {
                cJSON_AddStringToObject(ipv4, "DHCP", new_data->ipv4->dhcp);
            }
            cJSON_AddItemToObject(iface, "IPv4", ipv4);
        } else {
            cJSON_Delete(ipv4_addr);
            cJSON_Delete(ipv4);
        }
    }
    if (new_data->ipv6 && new_data->ipv6->address) {
        cJSON *ipv6 = cJSON_CreateObject();
        cJSON *ipv6_addr = cJSON_CreateArray();
        for (i = 0; new_data->ipv6->address[i]; i++) {
            if (strlen(new_data->ipv6->address[i])) {
                cJSON_AddItemToArray(ipv6_addr, cJSON_CreateString(new_data->ipv6->address[i]));
            }
        }
        if (cJSON_GetArraySize(ipv6_addr) > 0) {
            cJSON_AddItemToObject(ipv6, "address", ipv6_addr);
            if (new_data->ipv6->netmask) {
                cJSON *ipv6_netmask = cJSON_CreateArray();
                for (i = 0; new_data->ipv6->netmask[i]; i++) {
                    if (strlen(new_data->ipv6->netmask[i])) {
                        cJSON_AddItemToArray(ipv6_netmask, cJSON_CreateString(new_data->ipv6->netmask[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv6_netmask) > 0) {
                    cJSON_AddItemToObject(ipv6, "netmask", ipv6_netmask);
                } else {
                    cJSON_Delete(ipv6_netmask);
                }
            }
            if (new_data->ipv6->broadcast) {
                cJSON *ipv6_broadcast = cJSON_CreateArray();
                for (i = 0; new_data->ipv6->broadcast[i]; i++) {
                    if (strlen(new_data->ipv6->broadcast[i])) {
                        cJSON_AddItemToArray(ipv6_broadcast, cJSON_CreateString(new_data->ipv6->broadcast[i]));
                    }
                }
                if (cJSON_GetArraySize(ipv6_broadcast) > 0) {
                    cJSON_AddItemToObject(ipv6, "broadcast", ipv6_broadcast);
                } else {
                    cJSON_Delete(ipv6_broadcast);
                }
            }
            if (new_data->ipv6->metric > INT_MIN) {
                cJSON_AddNumberToObject(ipv6, "metric", new_data->ipv6->metric);
            }
            if (new_data->ipv6->gateway) {
                cJSON_AddStringToObject(ipv6, "gateway", new_data->ipv6->gateway);
            }
            if (new_data->ipv6->dhcp) {
                cJSON_AddStringToObject(ipv6, "DHCP", new_data->ipv6->dhcp);
            }
            cJSON_AddItemToObject(iface, "IPv6", ipv6);
        } else {
            cJSON_Delete(ipv6_addr);
            cJSON_Delete(ipv6);
        }
    }

    return object;
}

//
cJSON * program_json_event(program_entry_data * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *program = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "program");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "program", program);

    cJSON_AddStringToObject(program, "name", new_data->name);
    if (new_data->format) {
        cJSON_AddStringToObject(program, "format", new_data->format);
    }
    if (new_data->priority) {
        cJSON_AddStringToObject(program, "priority", new_data->priority);
    }
    if (new_data->group) {
        cJSON_AddStringToObject(program, "group", new_data->group);
    }
    if (new_data->size > LONG_MIN) {
        cJSON_AddNumberToObject(program, "size", new_data->size);
    }
    if (new_data->vendor) {
        cJSON_AddStringToObject(program, "vendor", new_data->vendor);
    }
    if (new_data->install_time) {
        cJSON_AddStringToObject(program, "install_time", new_data->install_time);
    }
    if (new_data->version) {
        cJSON_AddStringToObject(program, "version", new_data->version);
    }
    if (new_data->architecture) {
        cJSON_AddStringToObject(program, "architecture", new_data->architecture);
    }
    if (new_data->multi_arch) {
        cJSON_AddStringToObject(program, "multi-arch", new_data->multi_arch);
    }
    if (new_data->source) {
        cJSON_AddStringToObject(program, "source", new_data->source);
    }
    if (new_data->description) {
        cJSON_AddStringToObject(program, "description", new_data->description);
    }
    if (new_data->location) {
        cJSON_AddStringToObject(program, "location", new_data->location);
    }

    return object;
}

//
cJSON * hotfix_json_event(hotfix_entry_data * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "hotfix");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddStringToObject(object, "hotfix", new_data->hotfix);

    return object;
}

//
cJSON * port_json_event(port_entry_data * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *port = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "port");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "port", port);

    cJSON_AddStringToObject(port, "local_ip", new_data->local_ip);
    cJSON_AddNumberToObject(port, "local_port", new_data->local_port);
    if (new_data->remote_ip) {
        cJSON_AddStringToObject(port, "remote_ip", new_data->remote_ip);
    }
    if (new_data->remote_port > INT_MIN) {
        cJSON_AddNumberToObject(port, "remote_port", new_data->remote_port);
    }
    if (new_data->protocol) {
        cJSON_AddStringToObject(port, "protocol", new_data->protocol);
    }
    if (new_data->tx_queue > INT_MIN) {
        cJSON_AddNumberToObject(port, "tx_queue", new_data->tx_queue);
    }
    if (new_data->rx_queue > INT_MIN) {
        cJSON_AddNumberToObject(port, "rx_queue", new_data->rx_queue);
    }
    if (new_data->inode > INT_MIN) {
        cJSON_AddNumberToObject(port, "inode", new_data->inode);
    }
    if (new_data->state) {
        cJSON_AddStringToObject(port, "state", new_data->state);
    }
    if (new_data->pid > INT_MIN) {
        cJSON_AddNumberToObject(port, "PID", new_data->pid);
    }
    if (new_data->process) {
        cJSON_AddStringToObject(port, "process", new_data->process);
    }

    return object;
}

//
cJSON * process_json_event(process_entry_data * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *process = cJSON_CreateObject();
    int i = 0;

    cJSON_AddStringToObject(object, "type", "process");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "process", process);

    cJSON_AddNumberToObject(process, "pid", new_data->pid);
    cJSON_AddStringToObject(process, "name", new_data->name);
    if (new_data->state) {
        cJSON_AddStringToObject(process, "state", new_data->state);
    }
    if (new_data->ppid > INT_MIN) {
        cJSON_AddNumberToObject(process, "ppid", new_data->ppid);
    }
    if (new_data->utime > LLONG_MIN) {
        cJSON_AddNumberToObject(process, "utime", new_data->utime);
    }
    if (new_data->stime > LLONG_MIN) {
        cJSON_AddNumberToObject(process, "stime", new_data->stime);
    }
    if (new_data->cmd) {
        cJSON_AddStringToObject(process, "cmd", new_data->cmd);
        if (new_data->argvs)
        {
            cJSON *argvs = cJSON_CreateArray();
            for (i = 0; new_data->argvs[i]; i++) {
                if (strlen(new_data->argvs[i])) {
                    cJSON_AddItemToArray(argvs, cJSON_CreateString(new_data->argvs[i]));
                }
            }
            if (cJSON_GetArraySize(argvs) > 0) {
                cJSON_AddItemToObject(process, "argvs", argvs);
            } else {
                cJSON_Delete(argvs);
            }
        }
    }
    if (new_data->euser) {
        cJSON_AddStringToObject(process, "euser", new_data->euser);
    }
    if (new_data->ruser) {
        cJSON_AddStringToObject(process, "ruser", new_data->ruser);
    }
    if (new_data->suser) {
        cJSON_AddStringToObject(process, "suser", new_data->suser);
    }
    if (new_data->egroup) {
        cJSON_AddStringToObject(process, "egroup", new_data->egroup);
    }
    if (new_data->rgroup) {
        cJSON_AddStringToObject(process, "rgroup", new_data->rgroup);
    }
    if (new_data->sgroup) {
        cJSON_AddStringToObject(process, "sgroup", new_data->sgroup);
    }
    if (new_data->fgroup) {
        cJSON_AddStringToObject(process, "fgroup", new_data->fgroup);
    }
    if (new_data->priority > INT_MIN) {
        cJSON_AddNumberToObject(process, "priority", new_data->priority);
    }
    if (new_data->nice > INT_MIN) {
        cJSON_AddNumberToObject(process, "nice", new_data->nice);
    }
    if (new_data->size > LONG_MIN) {
        cJSON_AddNumberToObject(process, "size", new_data->size);
    }
    if (new_data->vm_size > LONG_MIN) {
        cJSON_AddNumberToObject(process, "vm_size", new_data->vm_size);
    }
    if (new_data->resident > LONG_MIN) {
        cJSON_AddNumberToObject(process, "resident", new_data->resident);
    }
    if (new_data->share > LONG_MIN) {
        cJSON_AddNumberToObject(process, "share", new_data->share);
    }
    if (new_data->start_time > LLONG_MIN) {
        cJSON_AddNumberToObject(process, "start_time", new_data->start_time);
    }
    if (new_data->pgrp > INT_MIN) {
        cJSON_AddNumberToObject(process, "pgrp", new_data->pgrp);
    }
    if (new_data->session > INT_MIN) {
        cJSON_AddNumberToObject(process, "session", new_data->session);
    }
    if (new_data->nlwp > INT_MIN) {
        cJSON_AddNumberToObject(process, "nlwp", new_data->nlwp);
    }
    if (new_data->tgid > INT_MIN) {
        cJSON_AddNumberToObject(process, "tgid", new_data->tgid);
    }
    if (new_data->tty > INT_MIN) {
        cJSON_AddNumberToObject(process, "tty", new_data->tty);
    }
    if (new_data->processor > INT_MIN) {
        cJSON_AddNumberToObject(process, "processor", new_data->processor);
    }

    return object;
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

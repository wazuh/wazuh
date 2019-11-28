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

wm_sys_t *sys = NULL;                           // Definition of global config

static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
static void wm_sys_destroy(wm_sys_t *sys);      // Destroy data
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON *wm_sys_dump(const wm_sys_t *sys);

// Syscollector module context definition

const wm_context WM_SYS_CONTEXT = {
    "syscollector",
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

// Module main function. It won't return

void* wm_sys_main(wm_sys_t *sys) {

    time_t time_start = 0;
    time_t time_sleep = 0;

    // Check configuration and show debug information

    wm_sys_setup(sys);

    sys_initialize_datastores();

    mtinfo(WM_SYS_LOGTAG, "Module started.");

    // First sleeping

    if (!sys->flags.scan_on_start) {
        time_start = time(NULL);

        // On first run, take into account the interval of time specified
        if (sys->state.next_time == 0) {
            sys->state.next_time = time_start + sys->interval;
        }

        if (sys->state.next_time > time_start) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            wm_delay(1000 * (sys->state.next_time - time_start));
        }
    } else {
        // Wait for Wazuh DB start
        wm_delay(1000);
    }

    // Main loop

    while (1) {

        mtinfo(WM_SYS_LOGTAG, "Starting evaluation.");

        // Get time and execute
        time_start = time(NULL);

        /* Network inventory */
        if (sys->flags.netinfo){
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
        }

        /* Operating System inventory */
        if (sys->flags.osinfo){
            #ifdef WIN32
                sys_os_windows(WM_SYS_LOCATION);
            #else
                sys_os_unix(queue_fd, WM_SYS_LOCATION);
            #endif
        }

        /* Hardware inventory */
        if (sys->flags.hwinfo){
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
        }

        /* Installed programs inventory */
        if (sys->flags.programinfo){
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
                print_programs_rbtree();
            #endif
        }

        /* Installed hotfixes inventory */
        if (sys->flags.hotfixinfo) {
            #ifdef WIN32
                sys_hotfixes(WM_SYS_LOCATION);
            #endif
        }
        /* Opened ports inventory */
        if (sys->flags.portsinfo){
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
        }

        /* Running processes inventory */
        if (sys->flags.procinfo){
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
                print_processes_rbtree();
            #endif
        }

        time_sleep = time(NULL) - time_start;

        mtinfo(WM_SYS_LOGTAG, "Evaluation finished.");

        if ((time_t)sys->interval >= time_sleep) {
            time_sleep = sys->interval - time_sleep;
            sys->state.next_time = sys->interval + time_start;
        } else {
            mterror(WM_SYS_LOGTAG, "Interval overtaken.");
            time_sleep = sys->state.next_time = 0;
        }

        if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_WRITE, &sys->state, sizeof(sys->state)) < 0)
            mterror(WM_SYS_LOGTAG, "Couldn't save running state: %s (%d)", strerror(errno), errno);

        // If time_sleep=0, yield CPU
        wm_delay(1000 * time_sleep);
    }

    return NULL;
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

    if (!sys->interval)
        sys->interval = WM_SYS_DEF_INTERVAL;
}


// Get read data

cJSON *wm_sys_dump(const wm_sys_t *sys) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sys = cJSON_CreateObject();

    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sys,"disabled","no"); else cJSON_AddStringToObject(wm_sys,"disabled","yes");
    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sys,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_sys,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_sys,"interval",sys->interval);
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

// Initialize hw_info structure

void init_hw_info(hw_info *info) {
    if(info != NULL) {
        info->cpu_name = NULL;
        info->cpu_cores = 0;
        info->cpu_MHz = 0.0;
        info->ram_total = 0;
        info->ram_free = 0;
        info->ram_usage = 0;
    }
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
    sys->programs_entry = rbtree_init();
    sys->processes_entry = rbtree_init();

    if (!sys->programs_entry || !sys->processes_entry) {
        merror_exit("Error while creating data structure: rb-tree init. Exiting."); // LCOV_EXCL_LINE
    }

    rbtree_set_dispose(sys->programs_entry, (void (*)(void *))free_program_data);
    rbtree_set_dispose(sys->processes_entry, (void (*)(void *))free_process_data);

    w_mutex_init(&sys->programs_entry_mutex, NULL);
    w_mutex_init(&sys->processes_entry_mutex, NULL);
}

// Initialize program_entry_data structure
void init_program_data_entry(program_entry_data * data) {
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
    data->installed = INT_MIN;
}

// Initialize process_entry_data structure
void init_process_data_entry(process_entry_data * data) {
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
    data->size = INT_MIN;
    data->vm_size = INT_MIN;
    data->resident = INT_MIN;
    data->share = INT_MIN;
    data->start_time = INT_MIN;
    data->utime = INT_MIN;
    data->stime = INT_MIN;
    data->pgrp = INT_MIN;
    data->session = INT_MIN;
    data->nlwp = INT_MIN;
    data->tgid = INT_MIN;
    data->tty = INT_MIN;
    data->processor = INT_MIN;
    data->running = INT_MIN;
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

// Analyze if insert new program or update an existing one
cJSON * analyze_program(program_entry_data * entry_data, int random_id, const char * timestamp) {
    cJSON * json_event = NULL;
    program_entry_data * saved_data = NULL;
    char * key = NULL;

    if (entry_data->name) {
        os_strdup(entry_data->name, key);
    }
    else {
        free_program_data(entry_data);
        mdebug1("Couldn't get the name of the program");
        return NULL;
    }

    w_mutex_lock(&sys->programs_entry_mutex);

    if (saved_data = (program_entry_data *) rbtree_get(sys->programs_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->programs_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->programs_entry_mutex);
            free_program_data(entry_data);
            mdebug1("Couldn't insert program into hash table: '%s'", key);
            return NULL;
        }
        json_event = program_json_event(NULL, entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->installed = 1;
        if (json_event = program_json_event(saved_data, entry_data, random_id, timestamp), json_event) {
            if (update_entry(sys->programs_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->programs_entry_mutex);
                free_program_data(entry_data);
                mdebug1("Couldn't update program in hash table: '%s'", key);
                return NULL;
            }
        } else {
            free_program_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->programs_entry_mutex);

    return json_event;
}

// Analyze if insert new process or update an existing one
cJSON * analyze_process(process_entry_data * entry_data, int random_id, const char * timestamp) {
    cJSON * json_event = NULL;
    process_entry_data * saved_data = NULL;
    char * key = NULL;

    if (entry_data->pid > INT_MIN) {
        os_calloc(12, sizeof(char), key);
        sprintf(key, "%d", entry_data->pid);
    }
    else {
        free_process_data(entry_data);
        mdebug1("Couldn't get the pid of the process");
        return NULL;
    }

    w_mutex_lock(&sys->processes_entry_mutex);

    if (saved_data = (process_entry_data *) rbtree_get(sys->processes_entry, key), !saved_data) {
        // New entry. Insert into hash table
        if (insert_entry(sys->processes_entry, key, (void *) entry_data) == -1) {
            w_mutex_unlock(&sys->processes_entry_mutex);
            free_process_data(entry_data);
            mdebug1("Couldn't insert process into hash table: '%s'", key);
            return NULL;
        }
        json_event = process_json_event(NULL, entry_data, random_id, timestamp);
    }
    else {
        // Checking for changes
        saved_data->running = 1;
        if (json_event = process_json_event(saved_data, entry_data, random_id, timestamp), json_event) {
            if (update_entry(sys->processes_entry, key, (void *) entry_data) == -1) {
                w_mutex_unlock(&sys->processes_entry_mutex);
                free_process_data(entry_data);
                mdebug1("Couldn't update process in hash table: '%s'", key);
                return NULL;
            }
        } else {
            free_process_data(entry_data);
        }
    }

    w_mutex_unlock(&sys->processes_entry_mutex);

    return json_event;
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
cJSON * program_json_event(program_entry_data * old_data, program_entry_data * new_data, int random_id, const char * timestamp) {
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
cJSON * process_json_event(process_entry_data * old_data, process_entry_data * new_data, int random_id, const char * timestamp) {
    cJSON *object = cJSON_CreateObject();
    cJSON *process = cJSON_CreateObject();
    int i = 0;

    cJSON_AddStringToObject(object, "type", "process");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "process", process);

    cJSON_AddNumberToObject(process, "pid", new_data->pid);
    if (new_data->name) {
        cJSON_AddStringToObject(process, "name", new_data->name);
    }
    if (new_data->state) {
        cJSON_AddStringToObject(process, "state", new_data->state);
    }
    if (new_data->ppid > INT_MIN) {
        cJSON_AddNumberToObject(process, "ppid", new_data->ppid);
    }
    if (new_data->utime > INT_MIN) {
        cJSON_AddNumberToObject(process, "utime", new_data->utime);
    }
    if (new_data->stime > INT_MIN) {
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
    if (new_data->size > INT_MIN) {
        cJSON_AddNumberToObject(process, "size", new_data->size);
    }
    if (new_data->vm_size > INT_MIN) {
        cJSON_AddNumberToObject(process, "vm_size", new_data->vm_size);
    }
    if (new_data->resident > INT_MIN) {
        cJSON_AddNumberToObject(process, "resident", new_data->resident);
    }
    if (new_data->share > INT_MIN) {
        cJSON_AddNumberToObject(process, "share", new_data->share);
    }
    if (new_data->start_time > INT_MIN) {
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

// Print programs hash table
void print_programs_rbtree() {
    char **keys;
    program_entry_data * node;
    int i = 0;

    w_mutex_lock(&sys->programs_entry_mutex);
    keys = rbtree_keys(sys->programs_entry);

    while(keys[i]) {
        node = (program_entry_data *) rbtree_get(sys->programs_entry, keys[i]);
        mdebug2("entry(%d) => (%s)'%s:%s'", i, keys[i], node->name, node->format);
        i++;
    }
    free_strarray(keys);
    w_mutex_unlock(&sys->programs_entry_mutex);

    return;
}

// Print processes hash table
void print_processes_rbtree() {
    char **keys;
    process_entry_data * node;
    int i = 0;

    w_mutex_lock(&sys->processes_entry_mutex);
    keys = rbtree_keys(sys->processes_entry);

    while(keys[i]) {
        node = (process_entry_data *) rbtree_get(sys->processes_entry, keys[i]);
        mdebug2("entry(%d) => (%s)'%d:%s'", i, keys[i], node->pid, node->name);
        i++;
    }
    free_strarray(keys);
    w_mutex_unlock(&sys->processes_entry_mutex);

    return;
}
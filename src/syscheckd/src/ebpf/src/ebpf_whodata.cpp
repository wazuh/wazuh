/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 27, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fstream>
#include <iostream>
#include <string>

#include "ebpf_whodata.hpp"  // Where fimebpf is declared with public pointers

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TASK_COMM_LEN 32
#define EBPF_HC_FILE "tmp/ebpf_hc"

// Global variables
static volatile bool epbf_hc_created = false;
static volatile bool event_received = false;
static bpf_object* global_obj = nullptr;  // Global BPF object pointer

// This struct must match the one in the BPF program
struct file_event {
    __u32 pid;                   // Process ID
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    char comm[TASK_COMM_LEN];    // Process command/name
    char filename[PATH_MAX];     // Filename passed to the syscall
    char cwd[PATH_MAX];          // Process working directory
    char event_type[16];         // Event type ("create", "delete", "mkdir")
    __u64 inode;                 // Inode number
    __u64 dev;                   // Device number
};

// Helper functions to convert numbers to string (caller must free the returned memory)
static char* uint_to_str(unsigned int num) {
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

static char* ulong_to_str(unsigned long long num) {
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

// Callback function to process events from the ring buffer.
// This function is called each time a new event is received.
int handle_event(void* ctx, void* data, size_t data_sz) {
    file_event* e = static_cast<file_event*>(data);
    char full_path[PATH_MAX];

    std::printf("handle_event");

    // Build the full path
    if (e->filename[0] == '/') {
        std::snprintf(full_path, PATH_MAX, "%s", e->filename);
    } else if (e->cwd[0] == '/') {
        std::snprintf(full_path, PATH_MAX, "%s/%s", e->cwd, e->filename);
    } else {
        return 1;
    }

    std::printf("Event: %s | PID: %u | UID: %u | GID: %u | Comm: %s | File: %s | CWD: %s | full_path: %s | inode: %d | dev: %d\n",
        e->event_type, e->pid, e->uid, e->gid, e->comm, e->filename, e->cwd, full_path, e->inode, e->dev);

    // Direct pointer usage from fimebpf
    directory_t* config = fimebpf::instance().m_fim_configuration_directory(full_path);
    if (config && (config->options & WHODATA_ACTIVE) && (config->options & EBPF_DRIVER)) {
        whodata_evt* w_evt = new whodata_evt;

        // Convert numeric fields to string
        w_evt->path = strdup(full_path);
        w_evt->process_name = strdup(e->comm);
        w_evt->user_id = uint_to_str(e->uid);
        w_evt->user_name = fimebpf::instance().m_get_user(e->uid);
        w_evt->group_id = uint_to_str(e->gid);
        w_evt->group_name = fimebpf::instance().m_get_group(e->gid);
        w_evt->inode = ulong_to_str(e->inode);
        w_evt->dev = ulong_to_str(e->dev);
        w_evt->process_id = e->pid;

        fimebpf::instance().m_fim_whodata_event(w_evt);
    }

    return 0;
}

int healthcheck_event(void* ctx, void* data, size_t data_sz) {
    file_event* e = static_cast<file_event*>(data);

    if (strstr(e->filename, EBPF_HC_FILE)) {
        event_received = true;
    }
    event_received = true;
    return 0;
}

int initialize_bpf_object(ring_buffer** rb, ring_buffer_sample_fn sample_cb) {
    bpf_object* obj = nullptr;
    int err;
    int rb_fd;

    // Obtain logging function pointer directly
    auto logFn = fimebpf::instance().m_loggingFunction;

    // Open the BPF object file
    obj = bpf_object__open_file("/var/ossec/bin/modern.bpf.o", nullptr);
    if (!obj) {
        logFn(LOG_ERROR, "Opening BPF object file failed.");
        return 1;
    }
    global_obj = obj;

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        logFn(LOG_ERROR, "Loading BPF object file failed.");
        bpf_object__close(obj);
        return 1;
    }

    // Attach all BPF programs
    bpf_program* prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            logFn(LOG_ERROR, "Attaching BPF program failed.");
            bpf_object__close(obj);
            return 1;
        }
    }

    // Retrieve the ring buffer map fd
    rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        logFn(LOG_ERROR, "Finding ring buffer map failed.");
        bpf_object__close(obj);
        return 1;
    }

    // Create the ring buffer
    *rb = ring_buffer__new(rb_fd, sample_cb, nullptr, nullptr);
    if (!*rb) {
        logFn(LOG_ERROR, "Creating ring buffer failed.");
        bpf_object__close(obj);
        return 1;
    }

    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

void fimebpf_initialize(directory_t *(*fim_conf)(const char *),
                        char *(*getUser)(int),
                        char *(*getGroup)(int),
                        void (*fimWhodataEvent)(whodata_evt *),
                        void (*loggingFn)(modules_log_level_t, const char *),
                        char *(*abspathFn)(const char *, char *, size_t))
{
    fimebpf::instance().initialize(fim_conf, getUser, getGroup, fimWhodataEvent, loggingFn, abspathFn);
}

int ebpf_whodata_healthcheck() {
    int err;
    ring_buffer* rb = nullptr;
    char ebpf_hc_abs_path[PATH_MAX] = {0};
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;

    if (initialize_bpf_object(&rb, healthcheck_event)) {
        return 1;
    }

    time_t start_time = time(nullptr);
    while (!event_received) {
        if (!epbf_hc_created) {
            // Use abspath pointer
            abspathFn(EBPF_HC_FILE, ebpf_hc_abs_path, sizeof(ebpf_hc_abs_path));

            std::ofstream file(ebpf_hc_abs_path);
            if (!file.is_open()) {
                logFn(LOG_ERROR, "Could not create healthcheck file.");
                break;
            }
            file << "Testing eBPF healthcheck\n";
            file.close();

            epbf_hc_created = true;
        }
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            logFn(LOG_ERROR, "Polling ring buffer failed.");
            break;
        }
        if (time(nullptr) - start_time >= 10) {
            logFn(LOG_ERROR, "Timeout healthcheck.");
            break;
        }
    }

    if (std::remove(ebpf_hc_abs_path) != 0) {
        logFn(LOG_ERROR, "Healthcheck file can't be removed.");
    }
    ring_buffer__free(rb);
    bpf_object__close(global_obj);

    if (!event_received) {
        return 1;
    }

    logFn(LOG_INFO, "Healthcheck for eBPF FIM whodata module success.");
    return 0;
}

int ebpf_whodata() {
    int err;
    ring_buffer* rb = nullptr;
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (initialize_bpf_object(&rb, handle_event)) {
        return 1;
    }

    // Poll the ring buffer indefinitely
    while (true) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            logFn(LOG_INFO, "Polling ring buffer failed.");
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(global_obj);
    return 0;
}

#ifdef __cplusplus
}
#endif

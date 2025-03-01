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
#include "modern.skel.h"
#include <fstream>
#include <iostream>
#include <string>

#include "ebpf_whodata.hpp"
#include "bpf_helpers.h"


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TASK_COMM_LEN 32
#define EBPF_HC_FILE "tmp/ebpf_hc"


// Global
static volatile bool epbf_hc_created = false;
static volatile bool event_received = false;
static bpf_object* global_obj = nullptr;
w_bpf_helpers_t * bpf_helpers = NULL;


struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char event_type[16];
    __u64 inode;
    __u64 dev;
};

static char* uint_to_str(unsigned int num) {
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}
static char* ulong_to_str(unsigned long long num) {
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

int handle_event(void* ctx, void* data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    file_event* e = static_cast<file_event*>(data);

    std::printf("Event: %s | PID: %u | UID: %u | GID: %u | Comm: %s | File: %s | inode: %llu | dev: %llu\n",
        e->event_type, e->pid, e->uid, e->gid, e->comm,
        e->filename,
        (unsigned long long)e->inode,
        (unsigned long long)e->dev);

    // Si encaja con tu config whodata
    directory_t* config = fimebpf::instance().m_fim_configuration_directory(e->filename);
    if (config && (config->options & WHODATA_ACTIVE) && (config->options & EBPF_DRIVER)) {
        whodata_evt* w_evt = new whodata_evt;
        w_evt->path = strdup(e->filename);
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
    (void)ctx; (void)data_sz;
    file_event* e = static_cast<file_event*>(data);

    if (strstr(e->filename, EBPF_HC_FILE)) {
        event_received = true;
    }
    return 0;
}


int initialize_bpf_object(ring_buffer** rb, ring_buffer_sample_fn sample_cb) {
    bpf_object* obj = nullptr;
    int err;
    auto logFn = fimebpf::instance().m_loggingFunction;

    bpf_helpers = (w_bpf_helpers_t *)calloc(1, sizeof(w_bpf_helpers_t));
    bpf_helpers->module = dlopen("/var/ossec/lib/libbpf.so", RTLD_LAZY);


    if (bpf_helpers->module) {
        bpf_helpers->bpf_object_destroy_skeleton = (bpf_object__destroy_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__destroy_skeleton");
        bpf_helpers->bpf_object_open_skeleton = (bpf_object__open_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__open_skeleton");
        bpf_helpers->bpf_object_load_skeleton = (bpf_object__load_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__load_skeleton");
        bpf_helpers->bpf_object_attach_skeleton = (bpf_object__attach_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__attach_skeleton");
        bpf_helpers->bpf_object_detach_skeleton = (bpf_object__detach_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__detach_skeleton");

        bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)dlsym(bpf_helpers->module, "bpf_object__open_file");
        bpf_helpers->bpf_object_load = (bpf_object__load_t)dlsym(bpf_helpers->module, "bpf_object__load");
        bpf_helpers->ring_buffer_new = (ring_buffer__new_t)dlsym(bpf_helpers->module, "ring_buffer__new");
        bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)dlsym(bpf_helpers->module, "ring_buffer__poll");
        bpf_helpers->ring_buffer_free = (ring_buffer__free_t)dlsym(bpf_helpers->module, "ring_buffer__free");
        bpf_helpers->bpf_object_close = (bpf_object__close_t)dlsym(bpf_helpers->module, "bpf_object__close");
        bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)dlsym(bpf_helpers->module, "bpf_object__next_program");
        bpf_helpers->bpf_program_attach = (bpf_program__attach_t)dlsym(bpf_helpers->module, "bpf_program__attach");
        bpf_helpers->bpf_object_find_map_fd_by_name = (bpf_object__find_map_fd_by_name_t)dlsym(bpf_helpers->module, "bpf_object__find_map_fd_by_name");

        // Check if all functions were loaded successfully
        if (bpf_helpers->bpf_object_open_file != NULL &&
            bpf_helpers->bpf_object_load != NULL &&
            bpf_helpers->ring_buffer_new != NULL &&
            bpf_helpers->ring_buffer_poll != NULL &&
            bpf_helpers->ring_buffer_free != NULL &&
            bpf_helpers->bpf_object_close != NULL &&
            bpf_helpers->bpf_object_next_program != NULL &&
            bpf_helpers->bpf_program_attach != NULL &&
            bpf_helpers->bpf_object_find_map_fd_by_name != NULL &&
            bpf_helpers->bpf_object_open_skeleton != NULL &&
            bpf_helpers->bpf_object_destroy_skeleton != NULL &&
            bpf_helpers->bpf_object_load_skeleton != NULL &&
            bpf_helpers->bpf_object_attach_skeleton != NULL &&
            bpf_helpers->bpf_object_detach_skeleton != NULL){
            logFn(LOG_INFO, "All functions loaded successfully from libbpf.so");
        } else {
            logFn(LOG_ERROR, "Failed to load some functions from libbpf.so");
            w_bpf_deinit(bpf_helpers);
            free(bpf_helpers);
            bpf_helpers = NULL;
        }
    } else {
        logFn(LOG_ERROR, "Unable to open libbpf.so");
        free(bpf_helpers);
        bpf_helpers = NULL;
    }
    obj = bpf_helpers->bpf_object_open_file("/var/ossec/bin/modern.bpf.o", nullptr);
    if (!obj) {
        logFn(LOG_ERROR, "Opening BPF object file failed.");
        w_bpf_deinit(bpf_helpers);
        free(bpf_helpers);
        bpf_helpers = NULL;
        return 1;
    }
    global_obj = obj;

    err = bpf_helpers->bpf_object_load(obj);
    if (err) {
        logFn(LOG_ERROR, "Loading BPF object file failed.");
        bpf_helpers->bpf_object_close(obj);
        w_bpf_deinit(bpf_helpers);
        free(bpf_helpers);
        bpf_helpers = NULL;
        return 1;
    }

    bpf_program* prog;
    bpf_object__for_each_program(bpf_helpers, prog, obj) {
        if (!bpf_helpers->bpf_program_attach(prog)) {
            logFn(LOG_ERROR, "Attaching BPF program failed.");
            bpf_helpers->bpf_object_close(obj);
            w_bpf_deinit(bpf_helpers);
            free(bpf_helpers);
            bpf_helpers = NULL;
            return 1;
        }
    }

    int rb_fd = bpf_helpers->bpf_object_find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        logFn(LOG_ERROR, "Finding ring buffer map failed.");
        bpf_helpers->bpf_object_close(obj);
        w_bpf_deinit(bpf_helpers);
        free(bpf_helpers);
        bpf_helpers = NULL;
        return 1;
    }

    *rb = bpf_helpers->ring_buffer_new(rb_fd, sample_cb, nullptr, nullptr);
    if (!*rb) {
        logFn(LOG_ERROR, "Creating ring buffer failed.");
        bpf_helpers->bpf_object_close(obj);
        w_bpf_deinit(bpf_helpers);
        free(bpf_helpers);
        bpf_helpers = NULL;
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
    fimebpf::instance().initialize(fim_conf, getUser, getGroup, fimWhodataEvent,
                                loggingFn, abspathFn);
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
        err = bpf_helpers->ring_buffer_poll(rb, 100);
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
    bpf_helpers->ring_buffer_free(rb);
    bpf_helpers->bpf_object_close(global_obj);

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

    while (true) {
        err = bpf_helpers->ring_buffer_poll(rb, 100);
        if (err < 0) {
            logFn(LOG_INFO, "Polling ring buffer failed.");
            break;
        }
    }

    bpf_helpers->ring_buffer_free(rb);
    bpf_helpers->bpf_object_close(global_obj);
    w_bpf_deinit(bpf_helpers);
    free(bpf_helpers);
    bpf_helpers = NULL;
    return 0;
}

#ifdef __cplusplus
}
#endif

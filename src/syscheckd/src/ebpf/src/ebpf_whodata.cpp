/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
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
#include <queue>
#include <mutex>
#include <memory>
#include <thread>
#include <bounded_queue.hpp>

#include "ebpf_whodata.hpp"
#include "bpf_helpers.h"


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TASK_COMM_LEN 32
#define EBPF_HC_FILE "tmp/ebpf_hc"
#define LIB_INSTALL_PATH "lib/libbpf.so"
#define BPF_OBJ_INSTALL_PATH "lib/modern.bpf.o"
#define WAIT_MS 500


// Global
static volatile bool epbf_hc_created = false;
static volatile bool event_received = false;
static bpf_object* global_obj = nullptr;
w_bpf_helpers_t * bpf_helpers = NULL;
int ebpf_whodata_queue_full_reported = 0;

struct file_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 inode;
    __u64 dev;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
    char cwd[PATH_MAX];
    char parent_cwd[PATH_MAX];
    char parent_comm[TASK_COMM_LEN];
};

fim::BoundedQueue<std::unique_ptr<file_event>> whodataEventQueue;

static char* uint_to_str(unsigned int num) {
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

static char* ulong_to_str(unsigned long long num) {
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

/* Callback for normal whodata events */
int handle_event(void* ctx, void* data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;

    file_event* e = static_cast<file_event*>(data);
    auto new_event = std::make_unique<file_event>(*e);
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!whodataEventQueue.push(std::move(new_event))) {
        if (!ebpf_whodata_queue_full_reported) {
            logFn(LOG_WARNING, FIM_FULL_EBPF_WHODATA_QUEUE);
            ebpf_whodata_queue_full_reported = 1;
        }
    }

    return 0;
}

/* Callback for healthcheck */
int healthcheck_event(void* ctx, void* data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    file_event* e = static_cast<file_event*>(data);

    if (strstr(e->filename, EBPF_HC_FILE)) {
        event_received = true;
    }
    return 0;
}

static int init_libbpf() {
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;
    char libbpf_path[PATH_MAX] = {0};

    if (!logFn || !abspathFn) {
        return 1;
    }

    abspathFn(LIB_INSTALL_PATH, libbpf_path, sizeof(libbpf_path));

    bpf_helpers = (w_bpf_helpers_t *)calloc(1, sizeof(w_bpf_helpers_t));
    if (!bpf_helpers) {
        return 1;
    }

    bpf_helpers->module = dlopen(libbpf_path, RTLD_LAZY);
    if (!bpf_helpers->module) {
        free(bpf_helpers);
        bpf_helpers = NULL;
        return 1;
    }

    /* Load all required symbols */
    bpf_helpers->bpf_object_destroy_skeleton = (bpf_object__destroy_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__destroy_skeleton");
    bpf_helpers->bpf_object_open_skeleton    = (bpf_object__open_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__open_skeleton");
    bpf_helpers->bpf_object_load_skeleton    = (bpf_object__load_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__load_skeleton");
    bpf_helpers->bpf_object_attach_skeleton  = (bpf_object__attach_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__attach_skeleton");
    bpf_helpers->bpf_object_detach_skeleton  = (bpf_object__detach_skeleton_t)dlsym(bpf_helpers->module, "bpf_object__detach_skeleton");

    bpf_helpers->bpf_object_open_file        = (bpf_object__open_file_t)dlsym(bpf_helpers->module, "bpf_object__open_file");
    bpf_helpers->bpf_object_load             = (bpf_object__load_t)dlsym(bpf_helpers->module, "bpf_object__load");
    bpf_helpers->ring_buffer_new             = (ring_buffer__new_t)dlsym(bpf_helpers->module, "ring_buffer__new");
    bpf_helpers->ring_buffer_poll            = (ring_buffer__poll_t)dlsym(bpf_helpers->module, "ring_buffer__poll");
    bpf_helpers->ring_buffer_free            = (ring_buffer__free_t)dlsym(bpf_helpers->module, "ring_buffer__free");
    bpf_helpers->bpf_object_close            = (bpf_object__close_t)dlsym(bpf_helpers->module, "bpf_object__close");
    bpf_helpers->bpf_object_next_program     = (bpf_object__next_program_t)dlsym(bpf_helpers->module, "bpf_object__next_program");
    bpf_helpers->bpf_program_attach          = (bpf_program__attach_t)dlsym(bpf_helpers->module, "bpf_program__attach");
    bpf_helpers->bpf_object_find_map_fd_by_name = (bpf_object__find_map_fd_by_name_t)dlsym(bpf_helpers->module, "bpf_object__find_map_fd_by_name");

    if (!bpf_helpers->bpf_object_open_file ||
        !bpf_helpers->bpf_object_load ||
        !bpf_helpers->ring_buffer_new ||
        !bpf_helpers->ring_buffer_poll ||
        !bpf_helpers->ring_buffer_free ||
        !bpf_helpers->bpf_object_close ||
        !bpf_helpers->bpf_object_next_program ||
        !bpf_helpers->bpf_program_attach ||
        !bpf_helpers->bpf_object_find_map_fd_by_name ||
        !bpf_helpers->bpf_object_open_skeleton ||
        !bpf_helpers->bpf_object_destroy_skeleton ||
        !bpf_helpers->bpf_object_load_skeleton ||
        !bpf_helpers->bpf_object_attach_skeleton ||
        !bpf_helpers->bpf_object_detach_skeleton)
    {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_LIB_LOAD);
        dlclose(bpf_helpers->module);
        free(bpf_helpers);
        bpf_helpers = NULL;
        return 1;
    }

    // Successfully loaded libbpf
    logFn(LOG_DEBUG_VERBOSE, FIM_EBPF_LIB_LOADED);
    return 0;
}

static void close_libbpf() {
    if (bpf_helpers) {
        if (bpf_helpers->module) {
            dlclose(bpf_helpers->module);
        }
        free(bpf_helpers);
        bpf_helpers = NULL;
    }
}

static int init_bpfobj() {
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;
    char bpfobj_path[PATH_MAX] = {0};

    if (!logFn || !abspathFn ) {
         return 1;
    }
    abspathFn(BPF_OBJ_INSTALL_PATH, bpfobj_path, sizeof(bpfobj_path));

    bpf_object* obj = bpf_helpers->bpf_object_open_file(bpfobj_path, nullptr);
    if (!obj) {
        char error_message[1024];
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_OBJ_OPEN, bpfobj_path, strerror(errno));
        logFn(LOG_ERROR, error_message);
        return 1;
    }
    global_obj = obj;

    int err = bpf_helpers->bpf_object_load(obj);
    if (err) {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_OBJ_LOAD);
        bpf_helpers->bpf_object_close(obj);
        global_obj = nullptr;
        return 1;
    }

    bpf_program* prog;
    bpf_object__for_each_program(bpf_helpers, prog, obj) {
        if (!bpf_helpers->bpf_program_attach(prog)) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_OBJ_ATTACH);
            bpf_helpers->bpf_object_close(obj);
            global_obj = nullptr;
            return 1;
        }
    }

    return 0;
}

static int init_ring_buffer(ring_buffer** rb, ring_buffer_sample_fn sample_cb) {
    auto logFn = fimebpf::instance().m_loggingFunction;
    if (!logFn) {
        return 1;
    }

    int rb_fd = bpf_helpers->bpf_object_find_map_fd_by_name(global_obj, "rb");
    if (rb_fd < 0) {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_MAP);
        bpf_helpers->bpf_object_close(global_obj);
        global_obj = nullptr;
        return 1;
    }

    *rb = bpf_helpers->ring_buffer_new(rb_fd, sample_cb, nullptr, nullptr);
    if (!*rb) {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_NEW);
        bpf_helpers->bpf_object_close(global_obj);
        global_obj = nullptr;
        return 1;
    }

    return 0;
}

/* Worker thread to pop events from whodataEventQueue */
void whodata_pop_events() {
    while (!fimebpf::instance().m_fim_shutdown_process_on()) {
        std::unique_ptr<file_event> event;

        if (!whodataEventQueue.pop(event, WAIT_MS)) {
            if (fimebpf::instance().m_fim_shutdown_process_on()) {
                return;
            }
        }

        if (event) {
            directory_t* config = fimebpf::instance().m_fim_configuration_directory(event->filename);
            if (config && (config->options & WHODATA_ACTIVE) && (config->options & EBPF_DRIVER)) {
                whodata_evt* w_evt = (whodata_evt*)calloc(1, sizeof(whodata_evt));

                w_evt->path = strdup(event->filename);
                w_evt->process_name = strdup(event->comm);
                w_evt->user_id = uint_to_str(event->uid);
                w_evt->user_name = fimebpf::instance().m_get_user(event->uid);
                w_evt->group_id = uint_to_str(event->gid);
                w_evt->group_name = fimebpf::instance().m_get_group(event->gid);
                w_evt->inode = ulong_to_str(event->inode);
                w_evt->dev = ulong_to_str(event->dev);
                w_evt->process_id = event->pid;
                w_evt->ppid = event->ppid;
                w_evt->cwd = strdup(event->cwd);
                w_evt->parent_cwd = strdup(event->parent_cwd);
                w_evt->parent_name = strdup(event->parent_comm);

                fimebpf::instance().m_fim_whodata_event(w_evt);
                fimebpf::instance().m_free_whodata_event(w_evt);
            }
        }
    }
}

#ifdef __cplusplus
extern "C" {
#endif

void fimebpf_initialize(directory_t *(*fim_conf)(const char *),
                        char *(*getUser)(int),
                        char *(*getGroup)(int),
                        void (*fimWhodataEvent)(whodata_evt *),
                        void (*freeWhodataEvent)(whodata_evt *),
                        void (*loggingFn)(modules_log_level_t, const char *),
                        char *(*abspathFn)(const char *, char *, size_t),
                        bool (*fimShutdownProcessOn)(),
                        unsigned int syscheckQueueSize) {
    fimebpf::instance().initialize(fim_conf, getUser, getGroup, fimWhodataEvent, freeWhodataEvent,
                                   loggingFn, abspathFn, fimShutdownProcessOn, syscheckQueueSize);
}

int ebpf_whodata_healthcheck() {
    ring_buffer* rb = nullptr;
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;
    char ebpf_hc_abs_path[PATH_MAX] = {0};
    char error_message[1024];

    whodataEventQueue.setMaxSize(fimebpf::instance().m_queue_size);

    if (!logFn || init_libbpf() || init_bpfobj() || init_ring_buffer(&rb, healthcheck_event)) {
        return 1;
    }

    time_t start_time = time(nullptr);
    while (!event_received) {
        int ret = bpf_helpers->ring_buffer_poll(rb, WAIT_MS);
        if (ret < 0) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            break;
        }
        if (time(nullptr) - start_time >= 10) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_HEALTHCHECK_TIMEOUT);
            break;
        }

        if (!epbf_hc_created) {
            abspathFn(EBPF_HC_FILE, ebpf_hc_abs_path, sizeof(ebpf_hc_abs_path));
            std::ofstream file(ebpf_hc_abs_path);
            if (!file.is_open()) {
                snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE, ebpf_hc_abs_path);
                logFn(LOG_ERROR, error_message);
                break;
            }
            file << "Testing eBPF healthcheck\n";
            file.close();
            epbf_hc_created = true;
        }
    }

    // Remove the tmp file
    if (std::remove(ebpf_hc_abs_path) != 0) {
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE_DEL, ebpf_hc_abs_path);
        logFn(LOG_ERROR, error_message);
    }

    // Free healthcheck ring buffer
    bpf_helpers->ring_buffer_free(rb);

    if (!event_received) {
        return 1;
    }

    logFn(LOG_INFO, FIM_EBPF_HEALTHCHECK_SUCCESS);
    return 0;
}

int ebpf_whodata() {
    auto logFn = fimebpf::instance().m_loggingFunction;
    ring_buffer* rb = nullptr;
    int ret;

    if (!logFn || init_ring_buffer(&rb, handle_event)) {
        return 1;
    }

    std::thread whodata_pop_thread(whodata_pop_events);
    whodata_pop_thread.detach();

    while (!fimebpf::instance().m_fim_shutdown_process_on()) {
        ret = bpf_helpers->ring_buffer_poll(rb, WAIT_MS);
        if (ret < 0) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            break;
        }
    }

    bpf_helpers->ring_buffer_free(rb);
    bpf_helpers->bpf_object_close(global_obj);
    global_obj = nullptr;
    w_bpf_deinit(bpf_helpers);
    close_libbpf();

    return 0;
}

#ifdef __cplusplus
}
#endif

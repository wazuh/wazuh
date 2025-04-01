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
#include <sstream>
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
#include <functional>

#include "ebpf_whodata.hpp"
#include "bpf_helpers.h"

#define KERNEL_VERSION_FILE "/proc/sys/kernel/osrelease"
#define EBPF_HC_FILE "tmp/ebpf_hc"
#define LIB_INSTALL_PATH "bpf"
#define BPF_OBJ_INSTALL_PATH "lib/modern.bpf.o"
#define WAIT_MS 500

// Global
static bpf_object* global_obj = nullptr;

std::unique_ptr<w_bpf_helpers_t> bpf_helpers = nullptr;
std::unique_ptr<DefaultDynamicLibraryWrapper> sym_load;
time_t (*w_time)(time_t*) = time;

int ebpf_kernel_queue_full_reported = 0;
fim::BoundedQueue<std::unique_ptr<dynamic_file_event>> kernelEventQueue;

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
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto confFn = fimebpf::instance().m_fim_configuration_directory;
    if (!logFn || !confFn) {
        return 0;
    }

    directory_t* config = confFn(e->filename);
    if (config && (config->options & WHODATA_ACTIVE)) {
        auto event = std::make_unique<dynamic_file_event>(dynamic_file_event{
            .filename    = std::string(e->filename),
            .cwd         = std::string(e->cwd),
            .parent_cwd  = std::string(e->parent_cwd),
            .comm        = std::string(e->comm),
            .parent_comm = std::string(e->parent_comm),
            .pid         = e->pid,
            .ppid        = e->ppid,
            .uid         = e->uid,
            .gid         = e->gid,
            .inode       = e->inode,
            .dev         = e->dev
        });
        if (!kernelEventQueue.push(std::move(event))) {
            if (!ebpf_kernel_queue_full_reported) {
                logFn(LOG_WARNING, FIM_FULL_EBPF_KERNEL_QUEUE);
                ebpf_kernel_queue_full_reported = 1;
            }
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

int check_invalid_kernel_version() {
    auto logFn = fimebpf::instance().m_loggingFunction;
    std::ifstream file(KERNEL_VERSION_FILE);

    if (!file) {
        return 1;
    }

    std::string version;
    file >> version;
    std::istringstream versionStream(version);
    std::vector<int> versionNumbers;
    std::string segment;

    while (std::getline(versionStream, segment, '.')) {
        try {
            versionNumbers.push_back(std::stoi(segment));
        } catch (...) {
            break;
        }
    }

    // Check we got minor and major versions
    if (versionNumbers.size() < 2) {
        return 1;
    }

    int major = versionNumbers[0];
    int minor = versionNumbers[1];

    if ((major < 5) || (major == 5 && minor < 8)) {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_INVALID_KERNEL);
        return 1;
    }
    else {
        return 0;
    }
}

int init_libbpf(std::unique_ptr<DynamicLibraryWrapper> local_sym_load) {
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;

    if (!logFn || !abspathFn || !bpf_helpers) {
        return 1;
    }

    if (!local_sym_load) {
        local_sym_load = std::make_unique<DefaultDynamicLibraryWrapper>();
    }

    if (!bpf_helpers->module) {
        bpf_helpers->module = local_sym_load->so__get_module_handle(LIB_INSTALL_PATH);
    }

    bpf_helpers->init_ring_buffer            = (init_ring_buffer_t)init_ring_buffer;
    bpf_helpers->ebpf_pop_events             = (ebpf_pop_events_t)ebpf_pop_events;
    bpf_helpers->init_bpfobj                 = (init_bpfobj_t)init_bpfobj;
    bpf_helpers->bpf_object_destroy_skeleton = (bpf_object__destroy_skeleton_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__destroy_skeleton");
    bpf_helpers->bpf_object_open_skeleton    = (bpf_object__open_skeleton_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__open_skeleton");
    bpf_helpers->bpf_object_load_skeleton    = (bpf_object__load_skeleton_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__load_skeleton");
    bpf_helpers->bpf_object_attach_skeleton  = (bpf_object__attach_skeleton_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__attach_skeleton");
    bpf_helpers->bpf_object_detach_skeleton  = (bpf_object__detach_skeleton_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__detach_skeleton");

    bpf_helpers->bpf_object_open_file        = (bpf_object__open_file_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__open_file");
    bpf_helpers->bpf_object_load             = (bpf_object__load_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__load");
    bpf_helpers->ring_buffer_new             = (ring_buffer__new_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "ring_buffer__new");
    bpf_helpers->ring_buffer_poll            = (ring_buffer__poll_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "ring_buffer__poll");
    bpf_helpers->ring_buffer_free            = (ring_buffer__free_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "ring_buffer__free");
    bpf_helpers->bpf_object_close            = (bpf_object__close_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__close");
    bpf_helpers->bpf_object_next_program     = (bpf_object__next_program_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__next_program");
    bpf_helpers->bpf_program_attach          = (bpf_program__attach_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_program__attach");
    bpf_helpers->bpf_object_find_map_fd_by_name = (bpf_object__find_map_fd_by_name_t)local_sym_load->getFunctionSymbol(bpf_helpers->module, "bpf_object__find_map_fd_by_name");


    /* Load all required symbols */
    if (!bpf_helpers->init_ring_buffer ||
        !bpf_helpers->ebpf_pop_events ||
        !bpf_helpers->init_bpfobj ||
        !bpf_helpers->bpf_object_open_file ||
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
        local_sym_load->freeLibrary(bpf_helpers->module);
        bpf_helpers.reset();
        return 1;
    }

    // Successfully loaded libbpf
    logFn(LOG_DEBUG_VERBOSE, FIM_EBPF_LIB_LOADED);
    return 0;
}

void close_libbpf(std::unique_ptr<DynamicLibraryWrapper> local_sym_load) {
    if (bpf_helpers) {
        if (bpf_helpers->module) {
            local_sym_load->freeLibrary(bpf_helpers->module);
        }
        bpf_helpers.reset();
    }
}

int init_bpfobj() {
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;
    char bpfobj_path[PATH_MAX] = {0};

    if (!logFn || !abspathFn ) {
         return 1;
    }
    abspathFn(BPF_OBJ_INSTALL_PATH, bpfobj_path, sizeof(bpfobj_path));

    bpf_object* obj = bpf_helpers->bpf_object_open_file(bpfobj_path, nullptr);
    if (!obj) {
        char error_message[4200];
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

int init_ring_buffer(ring_buffer** rb, ring_buffer_sample_fn sample_cb) {
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

/* Worker thread to pop events from kernelEventQueue */
void ebpf_pop_events(fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& local_kernelEventQueue) {
    auto logFn = fimebpf::instance().m_loggingFunction;
    if (!logFn) {
        return;
    }

    while (!fimebpf::instance().m_fim_shutdown_process_on()) {
        std::unique_ptr<dynamic_file_event> event;

        if (!local_kernelEventQueue.pop(event, WAIT_MS)) {
            if (fimebpf::instance().m_fim_shutdown_process_on()) {
                return;
            }
        }

        if (event) {
            whodata_evt* w_evt = (whodata_evt*)calloc(1, sizeof(whodata_evt));
            if (!w_evt) {
                continue;
            }
            w_evt->path         = strdup(event->filename.c_str());
            w_evt->process_name = strdup(event->comm.c_str());
            w_evt->user_id      = uint_to_str(event->uid);
            w_evt->user_name    = fimebpf::instance().m_get_user(event->uid);
            w_evt->group_id     = uint_to_str(event->gid);
            w_evt->group_name   = fimebpf::instance().m_get_group(event->gid);
            w_evt->inode        = ulong_to_str(event->inode);
            w_evt->dev          = ulong_to_str(event->dev);
            w_evt->process_id   = event->pid;
            w_evt->ppid         = event->ppid;
            w_evt->cwd          = strdup(event->cwd.c_str());
            w_evt->parent_cwd   = strdup(event->parent_cwd.c_str());
            w_evt->parent_name  = strdup(event->parent_comm.c_str());

            fimebpf::instance().m_fim_whodata_event(w_evt);
            fimebpf::instance().m_free_whodata_event(w_evt);
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
    char error_message[4200];

    if (!bpf_helpers) {
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
    }

    if (!bpf_helpers) {
        return 1;
    }

    if (!bpf_helpers->init_libbpf) {
        bpf_helpers->init_libbpf = (init_libbpf_t)init_libbpf;
    }

    if (!bpf_helpers->check_invalid_kernel_version) {
        bpf_helpers->check_invalid_kernel_version  = (check_invalid_kernel_version_t)check_invalid_kernel_version;
    }

    kernelEventQueue.setMaxSize(fimebpf::instance().m_queue_size);

    if (!logFn || bpf_helpers->check_invalid_kernel_version() || bpf_helpers->init_libbpf(std::move(sym_load)) || bpf_helpers->init_bpfobj() || bpf_helpers->init_ring_buffer(&rb, healthcheck_event)) {
        return 1;
    }

    time_t start_time = w_time(nullptr);
    while (!event_received) {
        int ret = bpf_helpers->ring_buffer_poll(rb, WAIT_MS);
        if (ret < 0) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            break;
        }
        if (w_time(nullptr) - start_time >= 10) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_HEALTHCHECK_TIMEOUT);
            break;
        }

        if (!ebpf_hc_created) {
            abspathFn(EBPF_HC_FILE, ebpf_hc_abs_path, sizeof(ebpf_hc_abs_path));
            std::ofstream file(ebpf_hc_abs_path);
            if (!file.is_open()) {
                snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE, ebpf_hc_abs_path);
                logFn(LOG_ERROR, error_message);
                break;
            }
            file << "Testing eBPF healthcheck\n";
            file.close();
            ebpf_hc_created = true;
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

    if (!logFn || bpf_helpers->init_ring_buffer(&rb, handle_event)) {
        return 1;
    }

    std::thread ebpf_pop_thread([&]() {
        bpf_helpers->ebpf_pop_events(kernelEventQueue);
    });
    ebpf_pop_thread.detach();

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
    close_libbpf(std::move(sym_load));

    return 0;
}

#ifdef __cplusplus
}
#endif

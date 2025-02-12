/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscheck.h"

#define TASK_COMM_LEN 32
#define EBPF_HC_FILE "tmp/ebpf_hc"

static volatile bool epbf_hc_created = false;
static volatile bool event_received = false;

// Structure must match the one in the BPF program
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

// Callback function to process events from the ring buffer.
// This function is called each time a new event is received.
int handle_event(void *ctx, void *data, size_t data_sz) {
    file_event *e = static_cast<file_event*>(data);
    char full_path[PATH_MAX];

    if (e->filename[0] == '/') {
        std::snprintf(full_path, PATH_MAX, "%s", e->filename);
    } elseif (e->cwd[0] == '/') {
        std::snprintf(full_path, PATH_MAX, "%s/%s", e->cwd, e->filename);
    } else {
        return 1;
    }

    // Check if path is configured with whodata eBPF driver
    directory_t *config = fim_configuration_directory(full_path);
    if ((config->options & WHODATA_ACTIVE) && (config->options & EBPF_DRIVER)) {
        whodata_evt *w_evt;

        w_evt->path = full_path;
        w_evt->process_name = e->comm;
        w_evt->user_id = e->uid;
        w_evt->user_name = get_user(e->uid);
        w_evt->group_id = e->gid;
        w_evt->group_name = get_group(e->gid);process_id
        w_evt->inode = e->inode;
        w_evt->dev = e->dev;
        w_evt->process_id = e->pid;

        fim_whodata_event(w_evt);
    }

    return 0;
}

int healthcheck_event(void *ctx, void *data, size_t data_sz) {
    file_event *e = static_cast<file_event*>(data);

    if (strstr(e->filename, EBPF_HC_FILE)) {
        event_received = true;
    }
    return 0;
}

int initialize_bpf_object(ring_buffer *rb, ring_buffer_sample_fn sample_cb) {
    bpf_object *obj = nullptr;
    int err;
    int rb_fd;

    // Open the BPF object file (assumes it is named "detect_mod.bpf.o")
    obj = bpf_object__open_file("/var/ossec/bin/modern.bpf.o", nullptr);
    if (!obj) {
        loggingFunction(LOG_ERROR, "Opening BPF object file failed.");
        return 1;
    }

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        loggingFunction(LOG_ERROR, "Loading BPF object file failed.");
        bpf_object__close(obj);
        return 1;
    }

    // Attach all BPF programs contained in the object
    bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            loggingFunction(LOG_ERROR, "Attaching BPF program failed.");
            bpf_object__close(obj);
            return 1;
        }
    }

    // Retrieve the file descriptor for the ring buffer map
    rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        loggingFunction(LOG_ERROR, "Finding ring buffer map failed.");
        bpf_object__close(obj);
        return 1;
    }

    // Create the ring buffer to receive events from the BPF program
    rb = ring_buffer__new(rb_fd, sample_cb, nullptr, nullptr);
    if (!rb) {
        loggingFunction(LOG_ERROR, "Creating ring buffer failed.");
        bpf_object__close(obj);
        return 1;
    }

    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

int ebpf_whodata_healthcheck() {
    int err;
    ring_buffer *rb = nullptr;

    if (initialize_bpf_object(rb, healthcheck_event)) {
        return 1;
    }

    time_t start_time = time(NULL);
    while (!event_received) {
        if (!epbf_hc_created) {
            char ebpf_hc_abs_path[PATH_MAX] = {'\0'};
            if (abspath(EBPF_HC_FILE, ebpf_hc_abs_path, sizeof(ebpf_hc_abs_path)) == NULL) {
                merror(FIM_ERROR_GET_ABSOLUTE_PATH, EBPF_HC_FILE, strerror(errno), errno);
                break;
            }

            std::ofstream file(ebpf_hc_abs_path);
            if (!file.is_open()) {
                std::cerr << "ERROR: No se pudo crear el archivo: " << ebpf_hc_abs_path << std::endl;
                break;
            }
            file << "Testing eBPF healthcheck\n";
            file.close();

            epbf_hc_created = true;
        }

        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            loggingFunction(LOG_ERROR, "Polling ring buffer failed.");
            break;
        }
        if (time(NULL) - start_time >= 10) {
            loggingFunction(LOG_ERROR, "Timeout healthcheck.");
            break;
        }
    }

    if (std::remove(ebpf_hc_abs_path) != 0) {
        loggingFunction(LOG_ERROR, "Healthcheck file can't be removed.");
    }
    ring_buffer__free(rb);
    bpf_object__close(obj);

    if (!event_received) {
        return 1;
    }

    loggingFunction(LOG_INFO, "Healthcheck for eBPF FIM whodata module success.");
    return 0;
}

// Function that initializes and executes the eBPF logic.
// This function will be called from another file and runs indefinitely,
// so termination should be handled externally.
int ebpf_whodata() {
    int err;
    ring_buffer *rb = nullptr;

    if (initialize_bpf_object(rb, handle_event)) {
        return 1;
    }

    // Poll the ring buffer in an infinite loop.
    // This loop runs indefinitely; termination should be handled externally.
    while (true) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err < 0) {
            loggingFunction(LOG_INFO, "Polling ring buffer failed.");
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}

#ifdef __cplusplus
}
#endif // _cplusplus

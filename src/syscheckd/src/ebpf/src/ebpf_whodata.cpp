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

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

// Structure must match the one in the BPF program
struct file_event {
    __u32 pid;                   // Process ID
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    char comm[TASK_COMM_LEN];    // Process command/name
    char filename[FILENAME_LEN]; // Filename passed to the syscall
    char cwd[FILENAME_LEN];      // Process working directory
    char event_type[16];         // Event type ("create", "delete", "mkdir")
};

// Callback function to process events from the ring buffer.
// This function is called each time a new event is received.
int handle_event(void *ctx, void *data, size_t data_sz) {
    file_event *e = static_cast<file_event*>(data);

    std::printf("Event: %s | PID: %u | UID: %u | GID: %u | Comm: %s | File: %s | CWD: %s\n",
                e->event_type, e->pid, e->uid, e->gid, e->comm, e->filename, e->cwd);
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

// Function that initializes and executes the eBPF logic.
// This function will be called from another file and runs indefinitely,
// so termination should be handled externally.
int ebpf_whodata() {
    bpf_object *obj = nullptr;
    int rb_fd;
    ring_buffer *rb = nullptr;
    int err;

    // Open the BPF object file (assumes it is named "detect_mod.bpf.o")
    obj = bpf_object__open_file("/var/ossec/bin/modern.bpf.o", nullptr);
    if (!obj) {
        std::fprintf(stderr, "ERROR: Opening BPF object file failed\n");
        return 1;
    }

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        std::fprintf(stderr, "ERROR: Loading BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach all BPF programs contained in the object
    bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            std::fprintf(stderr, "ERROR: Attaching BPF program failed\n");
            bpf_object__close(obj);
            return 1;
        }
    }

    // Retrieve the file descriptor for the ring buffer map
    rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        std::fprintf(stderr, "ERROR: Finding ring buffer map failed\n");
        bpf_object__close(obj);
        return 1;
    }

    // Create the ring buffer to receive events from the BPF program
    rb = ring_buffer__new(rb_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        std::fprintf(stderr, "ERROR: Creating ring buffer failed\n");
        bpf_object__close(obj);
        return 1;
    }

    // Poll the ring buffer in an infinite loop.
    // This loop runs indefinitely; termination should be handled externally.
    while (true) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err < 0) {
            std::fprintf(stderr, "ERROR: Polling ring buffer failed\n");
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

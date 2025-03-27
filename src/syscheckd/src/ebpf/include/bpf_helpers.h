/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

#include <dlfcn.h>
#include <stdint.h>
#include "logging_helper.h"
#include <bounded_queue.hpp>
#include <memory>

using whodata_deleter = std::function<void(whodata_evt*)>;

typedef __attribute__((aligned(4))) unsigned int __u32;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TASK_COMM_LEN 32


struct file_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    uint64_t inode;
    uint64_t dev;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
    char cwd[PATH_MAX];
    char parent_cwd[PATH_MAX];
    char parent_comm[TASK_COMM_LEN];
};

struct ring_buffer {
        struct epoll_event *events;
        struct ring **rings;
        size_t page_size;
        int epoll_fd;
        int ring_cnt;
};


typedef int (*bpf_object__open_skeleton_t)(struct bpf_object_skeleton *obj, const struct bpf_object_open_opts *opts);
typedef void (*bpf_object__destroy_skeleton_t)(struct bpf_object *obj);
typedef int (*bpf_object__load_skeleton_t)(struct bpf_object *obj);
typedef int (*bpf_object__attach_skeleton_t)(struct bpf_object *obj);
typedef void (*bpf_object__detach_skeleton_t)(struct bpf_object *obj);


typedef struct bpf_object *(*bpf_object__open_file_t)(const char *path, const struct bpf_object_open_opts *opts);
typedef int (*bpf_object__load_t)(struct bpf_object *obj);
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
typedef struct ring_buffer *(*ring_buffer__new_t)(int fd, ring_buffer_sample_fn sample_cb, void *ctx, void *flags);
typedef int (*ring_buffer__poll_t)(struct ring_buffer *rb, int timeout);
typedef void (*ring_buffer__free_t)(struct ring_buffer *rb);
typedef void (*bpf_object__close_t)(struct bpf_object *obj);
typedef struct bpf_program *(*bpf_object__next_program_t)(const struct bpf_object *obj, struct bpf_program *prog);
typedef int (*bpf_program__attach_t)(struct bpf_program *prog);
typedef int (*bpf_object__find_map_fd_by_name_t)(struct bpf_object *obj, const char *name);

// Function pointers to execute stateless requests to BPF
void (*bpf_object__destroy_skeleton)(struct bpf_object_skeleton *obj) = NULL;
int (*bpf_object__open_skeleton)(struct bpf_object_skeleton *obj, const struct bpf_object_open_opts *opts) = NULL;
int (*bpf_object__load_skeleton)(struct bpf_object_skeleton *obj) = NULL;
int (*bpf_object__attach_skeleton)(struct bpf_object_skeleton *obj) = NULL;
void (*bpf_object__detach_skeleton)(struct bpf_object_skeleton *obj) = NULL;

typedef int(*init_ring_buffer_t)(ring_buffer** rb, ring_buffer_sample_fn sample_cb);
typedef void(*whodata_pop_events_t)(fim::BoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>>& queue);
typedef void(*ebpf_pop_events_t)(fim::BoundedQueue<std::unique_ptr<file_event>>& kernel_queue, fim::BoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>>& queue);
typedef int(*check_invalid_kernel_version_t)();
typedef int(*init_libbpf_t)(std::unique_ptr<DynamicLibraryWrapper> sym_load);
typedef int(*init_bpfobj_t)();

/**
 * @brief Store helpers to execute stateless requests to BPF
 *
 */
typedef struct {
    void *module;

    bpf_object__open_file_t bpf_object_open_file;
    bpf_object__load_t bpf_object_load;
    ring_buffer__new_t ring_buffer_new;
    ring_buffer__poll_t ring_buffer_poll;
    ring_buffer__free_t ring_buffer_free;
    bpf_object__close_t bpf_object_close;
    bpf_object__next_program_t bpf_object_next_program;
    bpf_program__attach_t bpf_program_attach;
    bpf_object__find_map_fd_by_name_t bpf_object_find_map_fd_by_name;

    bpf_object__open_skeleton_t bpf_object_open_skeleton;
    bpf_object__destroy_skeleton_t bpf_object_destroy_skeleton;
    bpf_object__load_skeleton_t bpf_object_load_skeleton;
    bpf_object__attach_skeleton_t bpf_object_attach_skeleton;
    bpf_object__detach_skeleton_t bpf_object_detach_skeleton;

    init_ring_buffer_t init_ring_buffer;
    ebpf_pop_events_t ebpf_pop_events;
    whodata_pop_events_t whodata_pop_events;
    check_invalid_kernel_version_t check_invalid_kernel_version;
    init_libbpf_t init_libbpf;
    init_bpfobj_t init_bpfobj;

} w_bpf_helpers_t;


#define bpf_object__for_each_program(bpf_helpers, pos, obj)                  \
        for ((pos) = bpf_helpers->bpf_object_next_program((obj), NULL);     \
             (pos) != NULL;                                     \
             (pos) = bpf_helpers->bpf_object_next_program((obj), (pos)))



inline bool w_bpf_deinit(std::unique_ptr<w_bpf_helpers_t>& bpf_helpers) {
    bool result = false;

    if (bpf_helpers) {
        // Reset function pointers to NULL
        bpf_helpers->bpf_object_open_file = NULL;
        bpf_helpers->bpf_object_load = NULL;
        bpf_helpers->ring_buffer_new = NULL;
        bpf_helpers->ring_buffer_poll = NULL;
        bpf_helpers->ring_buffer_free = NULL;
        bpf_helpers->bpf_object_close = NULL;
        bpf_helpers->bpf_object_next_program = NULL;
        bpf_helpers->bpf_program_attach = NULL;
        bpf_helpers->bpf_object_find_map_fd_by_name = NULL;

        // Reset skeleton-specific function pointers to NULL
        bpf_helpers->bpf_object_open_skeleton = NULL;
        bpf_helpers->bpf_object_destroy_skeleton = NULL;
        bpf_helpers->bpf_object_load_skeleton = NULL;
        bpf_helpers->bpf_object_attach_skeleton = NULL;
        bpf_helpers->bpf_object_detach_skeleton = NULL;

        // eBPF FIM generic functions
	    bpf_helpers->init_ring_buffer = NULL;
	    bpf_helpers->ebpf_pop_events = NULL;
	    bpf_helpers->whodata_pop_events = NULL;
	    bpf_helpers->check_invalid_kernel_version = NULL;
	    bpf_helpers->init_libbpf = NULL;
	    bpf_helpers->init_bpfobj = NULL;

        // Free the loaded module (library)
        if (bpf_helpers->module != NULL) {
            dlclose(bpf_helpers->module);
            bpf_helpers.reset();
        }

        result = true;
    }

    return result;
}


int init_ring_buffer(ring_buffer** rb, ring_buffer_sample_fn sample_cb);
void ebpf_pop_events(fim::BoundedQueue<std::unique_ptr<file_event>>& kernel_queue, fim::BoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>>& queue);
void whodata_pop_events(fim::BoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>>& queue);
int check_invalid_kernel_version();
int init_libbpf(std::unique_ptr<DynamicLibraryWrapper> sym_load);
int init_bpfobj();


#endif // BPF_HELPERS_H


#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

// #include "sym_load.h"
#include <dlfcn.h>
#include "logging_helper.h"

typedef __attribute__((aligned(4))) unsigned int __u32;
typedef __attribute__((aligned(8))) unsigned long long __u64;

// Typedefs for libbpf function pointers defined on loader.skel.h
typedef int (*bpf_object__open_skeleton_t)(struct bpf_object_skeleton *obj, const struct bpf_object_open_opts *opts);
typedef void (*bpf_object__destroy_skeleton_t)(struct bpf_object *obj);
typedef int (*bpf_object__load_skeleton_t)(struct bpf_object *obj);
typedef int (*bpf_object__attach_skeleton_t)(struct bpf_object *obj);
typedef void (*bpf_object__detach_skeleton_t)(struct bpf_object *obj);


// Typedefs using here
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



/**
 * @brief Store helpers to execute stateless requests to BPF
 *
 */
typedef struct {
    void *module;  ///< Opaque reference to libbpf library (libbpf.so in this case)

    // Existing function pointers
    bpf_object__open_file_t bpf_object_open_file;
    bpf_object__load_t bpf_object_load;
    ring_buffer__new_t ring_buffer_new;
    ring_buffer__poll_t ring_buffer_poll;
    ring_buffer__free_t ring_buffer_free;
    bpf_object__close_t bpf_object_close;
    bpf_object__next_program_t bpf_object_next_program;
    bpf_program__attach_t bpf_program_attach;
    bpf_object__find_map_fd_by_name_t bpf_object_find_map_fd_by_name;

    // New function pointers for BPF skeleton operations
    bpf_object__open_skeleton_t bpf_object_open_skeleton;
    bpf_object__destroy_skeleton_t bpf_object_destroy_skeleton;
    bpf_object__load_skeleton_t bpf_object_load_skeleton;
    bpf_object__attach_skeleton_t bpf_object_attach_skeleton;
    bpf_object__detach_skeleton_t bpf_object_detach_skeleton;
} w_bpf_helpers_t;


#define bpf_object__for_each_program(bpf_helpers, pos, obj)                  \
        for ((pos) = bpf_helpers->bpf_object_next_program((obj), NULL);     \
             (pos) != NULL;                                     \
             (pos) = bpf_helpers->bpf_object_next_program((obj), (pos)))



bool w_bpf_deinit(w_bpf_helpers_t *bpf_helpers) {
    bool result = false;

    if (bpf_helpers != NULL) {
        // Free the loaded module (library)
        if (bpf_helpers->module != NULL) {
            dlclose(bpf_helpers->module);
            bpf_helpers->module = NULL;
        }

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

        result = true;
    }

    return result;
}

#endif // BPF_HELPERS_H

#ifndef BPF_OBJECT_SKELETON_H
#define BPF_OBJECT_SKELETON_H

struct bpf_object_open_opts;

struct bpf_map_skeleton {
        const char *name;
        struct bpf_map **map;
        void **mmaped;
};

struct bpf_prog_skeleton {
        const char *name;
        struct bpf_program **prog;
        struct bpf_link **link;
};

struct bpf_object_skeleton {
        size_t sz; /* size of this struct, for forward/backward compatibility */

        const char *name;
        const void *data;
        size_t data_sz;

        struct bpf_object **obj;

        int map_cnt;
        int map_skel_sz; /* sizeof(struct bpf_map_skeleton) */
        struct bpf_map_skeleton *maps;

        int prog_cnt;
        int prog_skel_sz; /* sizeof(struct bpf_prog_skeleton) */
        struct bpf_prog_skeleton *progs;
};

struct loader_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *rb;
                struct bpf_map *rodata_str1_1;
        } maps;
        struct {
                struct bpf_program *tracepoint__syscalls__sys_enter_openat;
                struct bpf_program *tracepoint__syscalls__sys_enter_unlinkat;
                struct bpf_program *tracepoint__syscalls__sys_enter_mkdirat;
        } progs;
        struct {
                struct bpf_link *tracepoint__syscalls__sys_enter_openat;
                struct bpf_link *tracepoint__syscalls__sys_enter_unlinkat;
                struct bpf_link *tracepoint__syscalls__sys_enter_mkdirat;
        } links;

#ifdef __cplusplus
        static inline struct loader_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
        static inline struct loader_bpf *open_and_load();
        static inline int load(struct loader_bpf *skel);
        static inline int attach(struct loader_bpf *skel);
        static inline void detach(struct loader_bpf *skel);
        static inline void destroy(struct loader_bpf *skel);
        static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

// Define the function types of libbpf that are being used
extern void (*bpf_object__destroy_skeleton)(struct bpf_object_skeleton *obj);
extern int (*bpf_object__open_skeleton)(struct bpf_object_skeleton *obj, const struct bpf_object_open_opts *opts);
extern int (*bpf_object__load_skeleton)(struct bpf_object_skeleton *obj);
extern int (*bpf_object__attach_skeleton)(struct bpf_object_skeleton *obj);
extern void (*bpf_object__detach_skeleton)(struct bpf_object_skeleton *obj);

#endif /* BPF_OBJECT_SKELETON_H */

/* Copyright (C) 2015, Wazuh Inc. — spike #37396 throwaway PoC.
 *
 * ONE program family emitting file-create events into ONE ring buffer,
 * carrying cgroup_id as the raw correlation key AND the FULL absolute path
 * (so a userspace consumer can filter by path prefix — see dispatcher.c).
 * Two SECs share the source:
 *   - lsm/file_open   : path via bpf_d_path()  (namespace-correct)
 *   - kprobe/vfs_open : path via a manual dentry walker (bpf_d_path is not
 *                       allowed in kprobe context). Walker ported from the
 *                       production modern.bpf.c (get_path_str_from_path).
 * The loader autoloads exactly one (see dispatcher.c). Proves: single source
 * of truth + per-consumer path-prefix filtering on BOTH attach paths.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define POC_PATH_MAX 256
#define FMODE_CREATED 0x4000
#define O_CREAT       0100

/* ---- per-CPU scratch for the manual path walker (kprobe variant) ---- */
#define MAX_PATH_LEN                    4096
#define MAX_PATH_COMPONENTS             320
#define MAX_PERCPU_ARRAY_SIZE           (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE          (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PATH_SIZE(x)              ((x) & (MAX_PATH_LEN - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

struct poc_event {
    __u32 pid;
    __u64 cgroup_id;
    char  path[POC_PATH_MAX];   /* FULL absolute path now, not just basename */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);   /* 4 MiB */
} rb SEC(".maps");

struct buffer { __u8 data[MAX_PERCPU_ARRAY_SIZE]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

/* bpf_d_path buffer (LSM variant) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[MAX_PATH_LEN]);
    __uint(max_entries, 1);
} dpath_map SEC(".maps");

/* Manual dentry walker — ported from production modern.bpf.c. Builds the
 * absolute path in reverse into a per-CPU buffer; returns a pointer via
 * path_str. Used by the kprobe variant where bpf_d_path is unavailable. */
static __always_inline long get_path_str_from_path(unsigned char **path_str,
                                                    struct path *path,
                                                    struct buffer *out_buf)
{
    long ret;
    struct dentry *dentry, *dentry_parent, *dentry_mnt;
    struct vfsmount *vfsmnt;
    struct mount *mnt, *mnt_parent;
    const unsigned char *name;
    size_t name_len;

    dentry = BPF_CORE_READ(path, dentry);
    vfsmnt = BPF_CORE_READ(path, mnt);
    mnt = container_of(vfsmnt, struct mount, mnt);
    mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

    size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
        dentry_parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == dentry_mnt || dentry == dentry_parent) {
            if (dentry != dentry_mnt)
                break;
            if (mnt != mnt_parent) {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
                continue;
            }
            break;
        }

        name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
        name     = (const unsigned char *)BPF_CORE_READ(dentry, d_name.name);
        name_len = name_len + 1;
        if (name_len > buf_off)
            break;

        volatile size_t new_buf_off = buf_off - name_len;
        ret = bpf_probe_read_kernel_str(
                  &(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buf_off)]),
                  name_len, (const char *)name);
        if (ret < 0)
            return ret;

        if (ret > 1) {
            buf_off -= 1;
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
            out_buf->data[buf_off] = '/';
            buf_off -= (ret - 1);
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        } else {
            break;
        }
        dentry = dentry_parent;
    }

    if (buf_off != 0) {
        buf_off -= 1;
        buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        out_buf->data[buf_off] = '/';
    }
    out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
    *path_str = &out_buf->data[buf_off];
    return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

static __always_inline void submit(const char *full_path) {
    struct poc_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;   /* ringbuf full -> kernel-side drop */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->path[0] = '\0';
    if (full_path)
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), full_path);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int is_create(struct file *file) {
    __u32 f_flags = BPF_CORE_READ(file, f_flags);
    fmode_t f_mode = BPF_CORE_READ(file, f_mode);
    return (f_flags & O_CREAT) || (f_mode & FMODE_CREATED);
}

/* Portable fallback: full path via manual walker. */
SEC("kprobe/vfs_open")
int BPF_KPROBE(kp_vfs_open, struct path *path, struct file *file) {
    if (!is_create(file))
        return 0;
    struct buffer *buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!buf)
        return 0;
    unsigned char *full_path = NULL;
    if (get_path_str_from_path(&full_path, path, buf) < 0)
        return 0;
    submit((const char *)full_path);
    return 0;
}

/* Modern upgrade: full path via bpf_d_path (namespace-correct). */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    if (!is_create(file))
        return 0;
    char *full_path = bpf_map_lookup_elem(&dpath_map, &(u32){0});
    if (!full_path)
        return 0;
    int ret = bpf_d_path(&file->f_path, full_path, MAX_PATH_LEN);
    if (ret < 0)
        return 0;
    submit(full_path);
    return 0;   /* LSM: 0 = allow */
}

char LICENSE[] SEC("license") = "GPL";

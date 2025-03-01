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

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 32

struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char event_type[16];
    __u64 inode;
    __u64 dev;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, char[ MAX_PATH_LEN ]);
    __uint(max_entries, 1024);
} open_path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, char[ MAX_PATH_LEN ]);
    __uint(max_entries, 1024);
} unlink_path_map SEC(".maps");

/* Define O_CREAT flag as in fcntl.h (octal 0100 = decimal 64) */
#define O_CREAT 0100

/* Some modes used (for example, creation) */
#define FMODE_CREATED 0x100000  // from fs.h in newer kernels

/* Absolute path extraction definitions */
#define MAX_PATH_SIZE 4096
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

/* Per-CPU buffer sizes and macros */
#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

/* Always-inline attribute for static functions */
#define statfunc static __attribute__((__always_inline__))

/* Per-CPU buffer structure for storing path strings */
struct buffer {
    u8 data[MAX_PERCPU_ARRAY_SIZE];
};

/* Map for file path extraction (per-cpu) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

/* Map for current working directory extraction (per-cpu) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} cwd_heap SEC(".maps");

/*
 * Function to reconstruct the full absolute path from a given struct path.
 * It traverses the dentry hierarchy and stores the constructed path in a per-CPU buffer.
 * The resulting pointer is returned via path_str.
 */
statfunc long get_path_str_from_path(unsigned char **path_str, struct path *path, struct buffer *out_buf) {
    long ret;
    struct dentry *dentry, *dentry_parent, *dentry_mnt;
    struct vfsmount *vfsmnt;
    struct mount *mnt, *mnt_parent;
    const unsigned char *name;
    size_t name_len;

    dentry = BPF_CORE_READ(path, dentry);
    vfsmnt = BPF_CORE_READ(path, mnt);
    /* Convert vfsmnt to mount structure */
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
        name = (const unsigned char *)BPF_CORE_READ(dentry, d_name.name);
        name_len = name_len + 1;
        if (name_len > buf_off)
            break;
        volatile size_t new_buff_offset = buf_off - name_len;
        ret = bpf_probe_read_kernel_str(
            &(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset)]),
            name_len,
            (const char *)name);
        if (ret < 0)
            return ret;
        if (ret > 1) {
            buf_off -= 1;
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
            out_buf->data[buf_off] = '/';
            buf_off -= ret - 1;
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

// Helper to safely extract inode and device information
static __always_inline void get_inode_dev(struct inode *inode_ptr, __u64 *inode, __u64 *dev) {
    if (!inode_ptr)
        return;

    bpf_probe_read_kernel(inode, sizeof(*inode), &inode_ptr->i_ino);

    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &inode_ptr->i_sb);
    if (sb) {
        __u32 dev32 = 0;
        bpf_probe_read_kernel(&dev32, sizeof(dev32), &sb->s_dev);
        *dev = dev32;
    }
}


static __always_inline void submit_event(const char *etype,
                                         const char *filename,
                                         __u64 ino,
                                         __u64 dev)
{
    struct file_event *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid >> 32;
    evt->gid = uid_gid;

    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    __builtin_memcpy(evt->event_type, etype, 16);

    bpf_probe_read_kernel_str(evt->filename, MAX_PATH_LEN, filename);

    evt->inode = ino;
    evt->dev   = dev;

    bpf_ringbuf_submit(evt, 0);
}

SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
     if (!path)
         return 0;

    struct file *file = (struct file *)PT_REGS_PARM2(ctx);
    if (!file)
        return 0;

    __u32 f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);
    // Detect created files
    if (!(f_mode & FMODE_CREATED))
        return 0;

    struct dentry *dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);
    if (!dentry) {
        return 0;
    }

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &d_inode->i_mode);

    if (((mode & 00170000) != 0100000))
        return 0;

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, path, string_buf) < 0)
        return 0;

    // Get inode and device information
    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    submit_event("create", (const char*) full_path, inode, dev);

    return 0;
}

SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file)
        return 0;

    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    if (!f_inode)
        return 0;

    __u32 f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);
    if ((f_mode & FMODE_CREATED))
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &f_inode->i_mode);

    if (((mode & 00170000) != 0100000))
        return 0;

    struct path fpath = BPF_CORE_READ(file, f_path);
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, &fpath, string_buf) < 0)
        return 0;

    // Get inode and device information
    __u64 inode = 0, dev = 0;
    get_inode_dev(f_inode, &inode, &dev);

    submit_event("modify", (const char*) full_path, inode, dev);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    const char *user_filename = (const char *)ctx->args[1];
    if (!user_filename)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    char path_buf[MAX_PATH_LEN];
    __builtin_memset(path_buf, 0, sizeof(path_buf));

    bpf_probe_read_user_str(path_buf, sizeof(path_buf), user_filename);

    bpf_map_update_elem(&unlink_path_map, &tid, path_buf, BPF_ANY);
    return 0;
}

SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    if (!dentry)
        return 0;

   struct inode *d_inode = NULL;
   bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
   if (!d_inode)
       return 0;

   __u32 mode = 0;
   bpf_probe_read_kernel(&mode, sizeof(mode), &d_inode->i_mode);

   if (((mode & 00170000) != 0100000))
       return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    char *stored_path = bpf_map_lookup_elem(&unlink_path_map, &tid);
    if (!stored_path)
        return 0;

    // Get inode and device information
    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    submit_event("delete", stored_path, inode, dev);
    bpf_map_delete_elem(&unlink_path_map, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

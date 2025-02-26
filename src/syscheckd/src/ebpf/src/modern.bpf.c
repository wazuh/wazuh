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

/* Maximum lengths and limits */
#define TASK_COMM_LEN 32
#define FILENAME_LEN 4096

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

/* Structure to hold file event data */
struct file_event {
    __u32 pid;                   // Process ID
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    char comm[TASK_COMM_LEN];    // Process command/name
    char filename[FILENAME_LEN]; // Filename or path
    char cwd[FILENAME_LEN];      // Process current working directory
    char event_type[16];         // Event type ("create", "write", "unlink", etc.)
    __u64 inode;                 // Inode number
    __u64 dev;                   // Device number
};

/* Ring buffer map to send events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} rb SEC(".maps");

/*
 * Function to reconstruct the full absolute path from a given struct path.
 * It traverses the dentry hierarchy and stores the constructed path in a per-CPU buffer.
 * The resulting pointer is returned via path_str.
 */
statfunc long get_path_str_from_path(u_char **path_str, struct path *path, struct buffer *out_buf) {
    long ret;
    struct dentry *dentry, *dentry_parent, *dentry_mnt;
    struct vfsmount *vfsmnt;
    struct mount *mnt, *mnt_parent;
    const u_char *name;
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
        name = (const u_char *)BPF_CORE_READ(dentry, d_name.name);
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

/*
 * Helper function to obtain a pointer to the current working directory (CWD)
 * from the per-cpu map 'cwd_heap'.
 */
static __always_inline u_char *get_cwd_ptr(void) {
    u32 zero = 0;
    struct buffer *buf = bpf_map_lookup_elem(&cwd_heap, &zero);
    if (!buf)
        return NULL;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs)
        return NULL;
    struct path *pwd = __builtin_preserve_access_index(&fs->pwd);
    u_char *cwd_str = NULL;
    if (get_path_str_from_path(&cwd_str, pwd, buf) < 0)
        return NULL;
    return cwd_str;
}

/*
 * Common function to submit an event to the ring buffer.
 */
static __always_inline int submit_event_common(const char *event_type,
                                               const char *filename,
                                               const char *cwd,
                                               __u64 inode,
                                               __u64 dev)
{
    struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid >> 32;
    e->gid = uid_gid;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->event_type, event_type, sizeof(e->event_type));

    bpf_probe_read_kernel_str(e->filename, FILENAME_LEN, filename);
    bpf_probe_read_kernel_str(e->cwd, FILENAME_LEN, cwd);

    e->inode = inode;
    e->dev = dev;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * DETECT CREATION
 *
 * 1) kprobe vfs_create -> typical creation
 * 2) kretprobe vfs_open con FMODE_CREATED
 */

/*
 * In some kernel versions, vfs_create has different signatures.
 * We'll assume (struct inode *dir, struct dentry *dentry, umode_t mode, bool want_excl)
 * or there's an extra param for user_namespace/mnt_idmap.
 */
SEC("kprobe/vfs_create")
int BPF_KPROBE(vfs_create, void *arg0, void *arg1, void *arg2)
{
    // The second argument is usually the dentry in older kernels.
    // In newer kernels with an extra param, the dentry might be arg2.
    // For simplicity, assume older style or fallback:
    struct dentry *dentry = (struct dentry *)arg1;
    if (!dentry)
        return 0;

    // We can store an event or do it immediately.
    // For simplicity, let's do it "immediately" like in the example probe_create.
    const char *name = (const char *)BPF_CORE_READ(dentry, d_name.name);

    // We won't do a start->end timing as in the example. We'll just emit an event now.
    u_char *cwd_ptr = get_cwd_ptr();
    if (!cwd_ptr)
        cwd_ptr = (u_char *)"";

    struct inode *inode = BPF_CORE_READ(dentry, d_inode); // might be null if not assigned yet
    __u64 ino = 0, dev = 0;
    if (inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
        struct super_block *sb = NULL;
        bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    submit_event_common("create", name, (const char *)cwd_ptr, ino, dev);
    return 0;
}

/*
 * kretprobe vfs_open -> catch FMODE_CREATED
 */
SEC("kretprobe/vfs_open")
int kretprobe__vfs_open(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_RC(ctx);
    if (!file)
        return 0;

    int fmode = BPF_CORE_READ(file, f_mode);
    if (!(fmode & FMODE_CREATED))
        return 0;  // not newly created

    // If newly created, we reconstruct the path
    struct path fpath = BPF_CORE_READ(file, f_path);
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, &fpath, string_buf) < 0)
        return 0;

    u_char *cwd_ptr = get_cwd_ptr();
    if (!cwd_ptr)
        cwd_ptr = (u_char *)"";

    // Extract inode, dev
    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    __u64 ino = 0, dev = 0;
    if (f_inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &f_inode->i_ino);
        struct super_block *sb = NULL;
        bpf_probe_read_kernel(&sb, sizeof(sb), &f_inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    submit_event_common("create", (const char *)full_path, (const char *)cwd_ptr, ino, dev);
    return 0;
}

/*
 * DETECT MODIFICATION -> kprobe vfs_write
 */
SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file)
        return 0;

    struct path fpath = BPF_CORE_READ(file, f_path);
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, &fpath, string_buf) < 0)
        return 0;

    u_char *cwd_ptr = get_cwd_ptr();
    if (!cwd_ptr)
        cwd_ptr = (u_char *)"";

    // Extract inode/dev
    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    __u64 ino = 0, dev = 0;
    if (f_inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &f_inode->i_ino);
        struct super_block *sb = NULL;
        bpf_probe_read_kernel(&sb, sizeof(sb), &f_inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    submit_event_common("write", (const char *)full_path, (const char *)cwd_ptr, ino, dev);
    return 0;
}

/*
 * DETECT REMOVAL -> kprobe vfs_unlink
 */
SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (!dentry)
        return 0;

    // filename
    const char *name = (const char *)BPF_CORE_READ(dentry, d_name.name);

    // inode, dev
    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
    __u64 ino = 0, dev = 0;
    if (inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
        struct super_block *sb = NULL;
        bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    u_char *cwd_ptr = get_cwd_ptr();
    if (!cwd_ptr)
        cwd_ptr = (u_char *)"";

    submit_event_common("unlink", name, (const char *)cwd_ptr, ino, dev);
    return 0;
}

/*
 * OPCIONAL: DETECT CREACIÓN DE DIRECTORIOS -> kprobe vfs_mkdir
 */
SEC("kprobe/vfs_mkdir")
int kprobe__vfs_mkdir(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (!dentry)
        return 0;

    const char *name = (const char *)BPF_CORE_READ(dentry, d_name.name);

    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
    __u64 ino = 0, dev = 0;
    if (inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
        struct super_block *sb = NULL;
        bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    u_char *cwd_ptr = get_cwd_ptr();
    if (!cwd_ptr)
        cwd_ptr = (u_char *)"";

    submit_event_common("mkdir", name, (const char *)cwd_ptr, ino, dev);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

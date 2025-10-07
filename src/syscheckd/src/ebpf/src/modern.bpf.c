/*
* Copyright (C) 2015, Wazuh Inc.
* All rights reserved.
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

#define MAX_PATH_LEN                    4096
#define TASK_COMM_LEN                   32
#define FMODE_CREATED                   0x4000
#define O_CREAT                         0100
#define O_ACCMODE                       00000003

/* These define general path extraction and buffer limits. */
#define LIMIT_PATH_SIZE(x)              ((x) & (MAX_PATH_LEN - 1))
#define MAX_PATH_COMPONENTS             320

#define MAX_PERCPU_ARRAY_SIZE           (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE          (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x)      ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

/* Always-inline attribute for helper functions. */
#define statfunc static inline

/*
* Used to hold all file-related event information
* when writing to the ring buffer.
*/
struct file_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 login_uid;
    __u64 inode;
    __u64 dev;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char cwd[MAX_PATH_LEN];
    char parent_cwd[MAX_PATH_LEN];
    char parent_name[TASK_COMM_LEN];
};

/*
* Per-CPU buffer used to store path strings
* while reconstructing paths in the kernel.
*/
struct buffer {
    /* Max possible size for a per-CPU array (in this configuration). */
    u8 data[MAX_PERCPU_ARRAY_SIZE];
};

/*
* A ring buffer map to send events from kernel to user space.
*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} rb SEC(".maps");

/*
* Per-CPU array used for storing paths during path reconstruction.
*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, char[MAX_PATH_LEN]);
    __uint(max_entries, 1);
} full_path_map SEC(".maps");

/*
* Per-CPU array used for storing CWD (current working directory) paths
* during path reconstruction.
*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} cwd_heap SEC(".maps");

// Kernel version check
extern int LINUX_KERNEL_VERSION __kconfig;

/*
* Concatenates a directory path and a filename into a full path.
* The result is stored in out_buf->data.
* The function returns the length of the concatenated string.
* The full path pointer is returned via full_path.
*
* This function ensures that the concatenated string does not exceed
* the maximum length of HALF_PERCPU_ARRAY_SIZE.
* It also handles the case where the directory path does not end with a '/'
* by appending it.
*/
statfunc long concat_strings_bpf(unsigned char **full_path,
                                 const char *dir_path,
                                 const char *filename,
                                 struct buffer *out_buf)
{
    long ret;
    size_t buf_off = 0;
    size_t max_len = HALF_PERCPU_ARRAY_SIZE; // Set the maximum length to half of the buffer size

    // Read the directory path (dir_path) into the buffer
    ret = bpf_probe_read_kernel_str(&out_buf->data[buf_off], max_len, (const char *)dir_path);
    if (ret < 0)
        return ret;
    size_t dir_path_len = ret;

    // Verify the length of the directory path
    if (dir_path_len == 0)
        return -1;

    // Update the buffer offset
    buf_off = dir_path_len - 1;

    // Check if the last character of dir_path is a null terminator
    if (&out_buf->data[buf_off - 1] != '/') {
        out_buf->data[buf_off] = '/';
        buf_off++;
    }

    // Recalculate the maximum length for the filename
    max_len = HALF_PERCPU_ARRAY_SIZE - buf_off;

    // Read the filename into the buffer
    ret = bpf_probe_read_kernel_str(&out_buf->data[buf_off], max_len, (const char *)filename);
    if (ret < 0)
        return ret;
    size_t filename_len = ret;

    // Assign pointer to the start of the concatenated string
    *full_path = &out_buf->data[0];

    // Return the total length of the concatenated string
    return (dir_path_len - 1) + (filename_len - 1);
}


/*
* Reconstructs the full absolute path from a struct path and stores it
* in out_buf->data. The result (pointer to the path string) is returned via path_str.
*
* This carefully walks up the dentry structure.
* 'HALF_PERCPU_ARRAY_SIZE' is used as a midpoint in the buffer
* to safely build the path in reverse order.
*/
statfunc long get_path_str_from_path(unsigned char **path_str,
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

        /* If we've reached the root of the filesystem or the parent is the same as current, stop. */
        if (dentry == dentry_mnt || dentry == dentry_parent) {
            if (dentry != dentry_mnt)
                break;
            /* Handle mountpoints going up */
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
        name_len = name_len + 1; // account for null terminator

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

    /* Insert leading '/' if we haven't consumed the entire buffer. */
    if (buf_off != 0) {
        buf_off -= 1;
        buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        out_buf->data[buf_off] = '/';
    }

    /* Null-terminate at the end of the buffer slice. */
    out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
    *path_str = &out_buf->data[buf_off];

    return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

/*
* Safely reads inode number and device information from an inode pointer.
*/
statfunc void get_inode_dev(struct inode *inode_ptr, __u64 *inode, __u64 *dev) {
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

/*
* Retrieves the current working directory path for the given task_struct.
* Stores the resulting path in 'dest' on success.
*/
statfunc int get_task_cwd(char *dest, int size, struct task_struct *task) {
    if (!task)
        return -1;

    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs)
        return -1;

    struct path pwd = BPF_CORE_READ(fs, pwd);
    struct buffer *buf = bpf_map_lookup_elem(&cwd_heap, &(u32){0});
    if (!buf)
        return -1;

    unsigned char *cwd_path = NULL;
    if (get_path_str_from_path(&cwd_path, &pwd, buf) < 0)
        return -1;

    bpf_probe_read_kernel_str(dest, size, (const char *)cwd_path);
    return 0;
}

/*
* Reserves space in the ring buffer for a file_event struct,
* populates it with file info, and submits it to user space.
*/
statfunc void submit_event(const char *filename,
                           __u64 ino,
                           __u64 dev)
{
    struct file_event *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt)
        return;

    /* Read current task to fill metadata */
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    /* PID and UID/GID */
    evt->pid = BPF_CORE_READ(current_task, tgid);
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid >> 32;
    evt->gid = uid_gid;

    /* Effective UID */
    kuid_t euid = BPF_CORE_READ(current_task, cred, euid);
    evt->euid = euid.val;

    /* Login UID (audit UID) */
    kuid_t loginuid;
    bpf_probe_read_kernel(&loginuid, sizeof(loginuid), &current_task->loginuid);
    evt->login_uid = loginuid.val;

    /* Command name of the current task */
    bpf_probe_read_kernel_str(evt->comm, TASK_COMM_LEN, (const char *)BPF_CORE_READ(current_task, comm));

    /* Copy the path/filename */
    bpf_probe_read_kernel_str(evt->filename, MAX_PATH_LEN, filename);

    /* Inode and device */
    evt->inode = ino;
    evt->dev   = dev;

    /* Clear buffers safely */
    bpf_probe_read_kernel_str(evt->cwd, MAX_PATH_LEN, "");
    bpf_probe_read_kernel_str(evt->parent_cwd, MAX_PATH_LEN, "");
    bpf_probe_read_kernel_str(evt->parent_name, TASK_COMM_LEN, "");

    /* Get process cwd */
    get_task_cwd(evt->cwd, MAX_PATH_LEN, current_task);

    /* Parent process info */
    evt->ppid = 0;
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    if (parent_task) {
        evt->ppid = BPF_CORE_READ(parent_task, tgid);

        bpf_probe_read_kernel_str(evt->parent_name, TASK_COMM_LEN,
                                  (const char *)BPF_CORE_READ(parent_task, comm));

        get_task_cwd(evt->parent_cwd, MAX_PATH_LEN, parent_task);
    }

    bpf_ringbuf_submit(evt, 0);
}

/*
* Intercepts vfs_open calls. Now it only reports if the file was newly created
* (FMODE_CREATED or O_CREAT set), for regular files.
*/
SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs *ctx)
{
if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 8, 0)) {
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    if (!path)
        return 0;

    struct file *file = (struct file *)PT_REGS_PARM2(ctx);
    if (!file)
        return 0;

    /* Check if the file is newly created */
    fmode_t f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);

    /* Also retrieve f_flags to handle creation if FMODE_CREATED fails */
    __u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);

    /* If not created, skip */
    if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT)) {
        return 0;
    }

    /* Retrieve the dentry. */
    struct dentry *dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);
    if (!dentry)
        return 0;

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &d_inode->i_mode);

    /* Only report regular files (0100000 is the S_IFREG mask). */
    if (((mode & 00170000) != 0100000))
        return 0;

    /* Reconstruct the path. */
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, path, string_buf) < 0)
        return 0;

    /* Extract inode/device. */
    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    /* Report file creation event. */
    submit_event((const char *)full_path, inode, dev);
}
    return 0;
}

SEC("kprobe/security_inode_setattr")
int kprobe__security_inode_setattr(struct pt_regs *ctx)
{
    struct dentry *dentry;
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 0, 0)) {
        dentry = (struct dentry *)PT_REGS_PARM1(ctx);
        if (!dentry) // Necessary condition to validate BPF program
            return 0;
    } else {
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
        if (!dentry) // Necessary condition to validate BPF program
            return 0;
    }

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &d_inode->i_mode);

    // Only monitor regular files (S_IFREG = 0100000)
    if ((mode & 00170000) != 0100000)
        return 0;

    // Extract filesystem information
    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb)
        return 0;

    struct mount *mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr)
        return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt)
        return 0;

    // Construct path
    struct path path = {
        .dentry = dentry,
        .mnt    = mnt
    };

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, &path, string_buf) < 0)
        return 0;

    // Extract inode and device
    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    // Submit event
    submit_event((const char *)full_path, inode, dev);

    return 0;
}

/*
* Intercepts vfs_unlink calls to detect file removal (delete).
* The path is retrieved from unlink_path_map to record which file was removed.
*/
SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs *ctx)
{
if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 8, 0)) {
    struct dentry *dentry;
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 12, 0)) {
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
        if (!dentry) // Necessary condition to validate BPF program
            return 0;
    } else {
        dentry = (struct dentry *)PT_REGS_PARM3(ctx);
        if (!dentry) // Necessary condition to validate BPF program
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

    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb)
        return 0;

    struct mount *mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr)
        return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt)
        return 0;

    /* Build a path struct from dentry + mnt. */
    struct path path = {
        .dentry = dentry,
        .mnt    = mnt
    };

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    if (get_path_str_from_path(&full_path, &path, string_buf) < 0)
        return 0;

    /* Extract inode/device. */
    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    submit_event((const char *)full_path, inode, dev);
}
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 8, 0)) {
    struct path *path = NULL;
    bpf_probe_read_kernel(&path, sizeof(path), &file->f_path);
    if (!path)
        return 0;

    /* Check if the file is newly created */
    fmode_t f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);
    if (!f_mode)
        return 0;

    /* Also retrieve f_flags to handle creation if FMODE_CREATED fails */
    __u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);
    if (!f_flags)
        return 0;

    /* If not created, skip */
    if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT) && !(f_flags & O_ACCMODE)) {
        return 0;
    }

    /* Retrieve the dentry. */
    struct dentry *dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);
    if (!dentry)
        return 0;

    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    if (!f_inode)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &f_inode->i_mode);
    if (!mode)
        return 0;

    /* Only report regular files (0100000 is the S_IFREG mask). */
    if (((mode & 00170000) != 0100000))
        return 0;

    char *full_path = bpf_map_lookup_elem(&full_path_map, &(u32){0});
    if (!full_path)
        return 0;

    int ret = bpf_d_path(&file->f_path, full_path, MAX_PATH_LEN);
    if (ret < 0)
        return 0;

    /* Extract inode/device. */
    __u64 inode = 0, dev = 0;
    get_inode_dev(f_inode, &inode, &dev);

    submit_event((const char *)full_path, inode, dev);
}
    return 0;
}


SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *path, struct dentry *dentry)
{
if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 8, 0)) {
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &d_inode->i_mode);
    if (!mode)
        return 0;

    /* Only report regular files (0100000 is the S_IFREG mask). */
    if (((mode & 00170000) != 0100000))
        return 0;

    char *dir_path = bpf_map_lookup_elem(&full_path_map, &(u32){0});
    if (!dir_path)
        return 0;

    int ret = bpf_d_path(path, dir_path, MAX_PATH_LEN);
    if (ret < 0)
        return 0;

    /* Get the file name pointer from dentry->d_name.name */
    const char *file_name_ptr;
    bpf_probe_read_kernel(&file_name_ptr, sizeof(file_name_ptr), &dentry->d_name.name);
    if (!file_name_ptr)
        return 0;

    /* Reconstruct the path. */
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf)
        return 0;

    u8 *full_path = NULL;
    ret = concat_strings_bpf(&full_path, dir_path, file_name_ptr, string_buf);
    if (ret < 0)
        return 0;

    /* Extract inode/device. */
    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    submit_event((const char *)full_path, inode, dev);
}
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum length for process command and file names
#define TASK_COMM_LEN 32
#define FILENAME_LEN 4096

// Define O_CREAT flag as in fcntl.h (octal 0100 = decimal 64)
#define O_CREAT 0100

/*
 * Absolute path extraction functions and definitions.
 * These functions allow us to reconstruct the full absolute path (e.g., CWD)
 * by traversing the dentry hierarchy.
 */

// Define constants for absolute path extraction
#define MAX_PATH_SIZE 4096           // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

// Define per-CPU buffer sizes and macros for limiting offsets
#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

// Define the always-inline attribute for static functions
#define statfunc static __attribute__((__always_inline__))

// Define a buffer structure for storing path strings
struct buffer {
    u8 data[MAX_PERCPU_ARRAY_SIZE];
};

// Define a per-CPU array map to store the buffers
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

// Function to get a per-CPU buffer from the heaps_map
statfunc struct buffer *get_buffer() {
    u32 zero = 0;
    return (struct buffer *)bpf_map_lookup_elem(&heaps_map, &zero);
}

// Structure to hold file event data
struct file_event {
    __u32 pid;                   // Process ID
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    char comm[TASK_COMM_LEN];    // Process command/name
    char filename[FILENAME_LEN]; // Filename passed to the syscall
    char cwd[FILENAME_LEN];      // Process CWD
    char event_type[16];         // Type of event ("create", "delete", "mkdir")
    __u64 inode;                 // Inode number
    __u64 dev;                   // Device number
};

// Define a ring buffer map to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} rb SEC(".maps");

// Function to reconstruct the full absolute path from a given struct path.
// This function traverses the dentry hierarchy and stores the constructed
// path in a per-CPU buffer. The resulting pointer is returned via path_str.
statfunc long get_path_str_from_path(u_char **path_str, struct path *path, struct buffer *out_buf) {
    long ret;
    struct dentry *dentry, *dentry_parent, *dentry_mnt;
    struct vfsmount *vfsmnt;
    struct mount *mnt, *mnt_parent;
    const u_char *name;
    size_t name_len;

    // Read the dentry and vfsmount from the given path
    dentry = BPF_CORE_READ(path, dentry);
    vfsmnt = BPF_CORE_READ(path, mnt);
    // Convert vfsmnt to mount structure using container_of
    mnt = container_of(vfsmnt, struct mount, mnt);
    mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

    // Initialize the buffer offset to half the per-CPU buffer size
    size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        // Get the mount root and parent of the current dentry
        dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
        dentry_parent = BPF_CORE_READ(dentry, d_parent);

        // Check if we have reached the mount root or the current dentry's parent is itself
        if (dentry == dentry_mnt || dentry == dentry_parent) {
            if (dentry != dentry_mnt) {
                // We reached root, but not mount root - unexpected state, break out
                break;
            }
            if (mnt != mnt_parent) {
                // Reached mount root, but not the global root - continue with the mount point path
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
                continue;
            }
            // Global root reached - the path is fully parsed
            break;
        }

        // Add this dentry's name to the path string
        name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
        name = BPF_CORE_READ(dentry, d_name.name);

        // Increase name length by one to account for the slash separator
        name_len = name_len + 1;
        // Check if the string buffer is large enough for the dentry name
        if (name_len > buf_off) {
            break;
        }
        // Satisfy the verifier by using a volatile variable for new buffer offset
        volatile size_t new_buff_offset = buf_off - name_len;
        ret = bpf_probe_read_kernel_str(
            &(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset)]),
            name_len,
            name);
        if (ret < 0) {
            return ret;
        }

        if (ret > 1) {
            // Remove the null byte termination and add a slash instead
            buf_off -= 1;
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
            out_buf->data[buf_off] = '/';
            buf_off -= ret - 1;
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        } else {
            // If the read size is 0 or 1, this is an error (path cannot be null or empty)
            break;
        }
        // Move to the parent dentry for the next iteration
        dentry = dentry_parent;
    }

    // Add a leading slash if there is space in the buffer
    if (buf_off != 0) {
        buf_off -= 1;
        buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        out_buf->data[buf_off] = '/';
    }

    // Null-terminate the path string
    out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
    // Set the output pointer to the beginning of the constructed path
    *path_str = &out_buf->data[buf_off];
    return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

// Helper function to submit an event to the ring buffer
static __always_inline int submit_event(const char *event_type, const char *filename) {
    struct file_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Get process information
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->gid = uid_gid;
    e->uid = uid_gid >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Set event type (e.g., "create", "delete", "mkdir")
    __builtin_memcpy(e->event_type, event_type, sizeof(e->event_type));

    // Read the filename from user memory
    bpf_probe_read_user_str(e->filename, FILENAME_LEN, filename);

    // Extract the absolute current working directory (CWD)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    u_char *cwd_path = NULL;
    if (fs) {
        struct path *pwd = __builtin_preserve_access_index(&fs->pwd);
        struct buffer *string_buf = get_buffer();
        if (string_buf) {
            get_path_str_from_path(&cwd_path, pwd, string_buf);
        }
    }

    bpf_probe_read_kernel_str(e->cwd, FILENAME_LEN, cwd_path);

    // Get the inode number and device of the file
    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);

    __u64 ino = 0;
    __u64 dev = 0;
    if (f_inode) {
        // Read the inode
        bpf_probe_read_kernel(&ino, sizeof(ino), &f_inode->i_ino);
        e->inode = ino;

        // Read pointer to the superblock to obtain the device
        struct super_block *sb = NULL;
        bpf_probe_read_kernel(&sb, sizeof(sb), &f_inode->i_sb);
        if (sb) {
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
            e->dev = dev;
        } else {
            e->dev = 0;
        }
    } else {
        e->inode = 0;
        e->dev = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Tracepoint for sys_enter_openat.
 *
 * This tracepoint receives a pointer to a structure (struct trace_event_raw_sys_enter)
 * that contains an array of arguments (args[]). For openat:
 *   args[0] -> int dfd
 *   args[1] -> const char *filename
 *   args[2] -> int flags
 *   args[3] -> mode_t mode
 *
 * We check if the O_CREAT flag is present in args[2] to consider it as a creation event.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    // Retrieve the filename argument
    const char *filename = (const char *)ctx->args[1];

    // Retrieve flags argument
    int flags = ctx->args[2];

    // If the O_CREAT flag is set, we consider it as a file creation event
    if (flags & O_CREAT) {
        submit_event("openat", filename);
    }

    return 0;
}

/*
 * Tracepoint for sys_enter_unlinkat.
 *
 * This syscall is used for deleting files.
 *   args[0] -> int dfd
 *   args[1] -> const char *pathname
 *   args[2] -> int flags
 */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname = (const char *)ctx->args[1];

    submit_event("unlinkat", pathname);
    return 0;
}

/*
 * Tracepoint for sys_enter_mkdirat.
 *
 * This syscall is used for creating directories.
 *   args[0] -> int dfd
 *   args[1] -> const char *pathname
 *   args[2] -> mode_t mode
 */
SEC("tracepoint/syscalls/sys_enter_mkdirat")
int tracepoint__syscalls__sys_enter_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname = (const char *)ctx->args[1];

    submit_event("mkdirat", pathname);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

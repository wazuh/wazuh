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

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    const char *user_filename = (const char *)ctx->args[1];
    if (!user_filename)
        return 0;

    char path_buf[MAX_PATH_LEN];
    __builtin_memset(path_buf, 0, sizeof(path_buf));

    bpf_probe_read_user_str(path_buf, sizeof(path_buf), user_filename);

    bpf_map_update_elem(&open_path_map, &tid, path_buf, BPF_ANY);
    return 0;
}

SEC("kretprobe/do_filp_open")
int kretprobe__do_filp_open(struct pt_regs *ctx)
{
    struct file *file = (struct file*)PT_REGS_RC(ctx);
    if (!file)
        return 0;

    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    if (!f_inode)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &f_inode->i_mode);

    if (((mode & 00170000) != 0100000))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    char *stored_path = bpf_map_lookup_elem(&open_path_map, &tid);
    if (!stored_path)
        return 0;

    __u64 ino = 0;
    bpf_probe_read_kernel(&ino, sizeof(ino), &f_inode->i_ino);

    __u64 dev = 0;
    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &f_inode->i_sb);
    if (sb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    submit_event("change", stored_path, ino, dev);

    bpf_map_delete_elem(&open_path_map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    const char *user_filename = (const char *)ctx->args[1];
    if (!user_filename)
        return 0;

    char path_buf[MAX_PATH_LEN];
    __builtin_memset(path_buf, 0, sizeof(path_buf));

    bpf_probe_read_user_str(path_buf, sizeof(path_buf), user_filename);

    bpf_map_update_elem(&unlink_path_map, &tid, path_buf, BPF_ANY);
    return 0;
}

SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs *ctx)
{
    // 2do arg: dentry
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (!dentry)
        return 0;

    // leemos inode
    struct inode *inode_ptr = NULL;
    bpf_probe_read_kernel(&inode_ptr, sizeof(inode_ptr), &dentry->d_inode);
    if (!inode_ptr)
        return 0;

    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &inode_ptr->i_mode);
    if (((mode & 00170000) != 0100000))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    char *stored_path = bpf_map_lookup_elem(&unlink_path_map, &tid);
    if (!stored_path)
        return 0;

    __u64 ino = 0;
    bpf_probe_read_kernel(&ino, sizeof(ino), &inode_ptr->i_ino);

    __u64 dev = 0;
    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &inode_ptr->i_sb);
    if (sb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    submit_event("unlink", stored_path, ino, dev);

    bpf_map_delete_elem(&unlink_path_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

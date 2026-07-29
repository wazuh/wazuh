/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) — FILE event class only, per this pass's scope.
 * Path-walking logic ported from the FIM-embedded src/syscheckd/src/ebpf/
 * src/modern.bpf.c (proven working code, unchanged in substance) — the
 * change here is architectural: this program emits the shared, versioned
 * rt_file_event contract (rt_event_contract.h) instead of FIM's own ad hoc
 * struct, and every hook is autoload-gated independently by the loader
 * (rt_engine.c) per the calling consumer's rt_filter, not hardcoded here.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "rt_event_contract.h"

#define FMODE_CREATED 0x4000
#define O_CREAT       0100
#define O_ACCMODE     00000003

#define MAX_PATH_COMPONENTS  320
#define PERCPU_BUF_SIZE      (1 << 15)
#define HALF_BUF_SIZE        (PERCPU_BUF_SIZE >> 1)
#define LIMIT_HALF(x)        ((x) & (HALF_BUF_SIZE - 1))

#define statfunc static inline

struct buffer
{
    __u8 data[PERCPU_BUF_SIZE];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[RT_PATH_MAX]);
    __uint(max_entries, 1);
} dpath_map SEC(".maps");

/* Single-slot drop counter (#37396 backpressure design): incremented every
 * time bpf_ringbuf_reserve() fails, read-and-reset into the next
 * successfully-submitted event's `dropped`/RT_F_DROPS_BEFORE, so loss is
 * visible in-band instead of only in a log line. */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} drops_map SEC(".maps");

extern int LINUX_KERNEL_VERSION __kconfig;

statfunc void bump_drop_counter(void)
{
    __u32 key = 0;
    __u32* counter = bpf_map_lookup_elem(&drops_map, &key);
    if (counter)
    {
        __sync_fetch_and_add(counter, 1);
    }
}

statfunc __u32 take_drop_counter(void)
{
    __u32 key = 0;
    __u32* counter = bpf_map_lookup_elem(&drops_map, &key);
    if (!counter)
    {
        return 0;
    }
    __u32 value = *counter;
    *counter = 0;
    return value;
}

/* Manual dentry/vfsmount walker for the kprobe attach path (bpf_d_path is
 * not callable from kprobe context). Ported verbatim from modern.bpf.c's
 * get_path_str_from_path(). */
statfunc long get_path_str_from_path(unsigned char** path_str, struct path* path, struct buffer* out_buf)
{
    long ret;
    struct dentry *dentry, *dentry_parent, *dentry_mnt;
    struct vfsmount* vfsmnt;
    struct mount *mnt, *mnt_parent;
    const unsigned char* name;
    size_t name_len;

    dentry = BPF_CORE_READ(path, dentry);
    vfsmnt = BPF_CORE_READ(path, mnt);
    mnt = container_of(vfsmnt, struct mount, mnt);
    mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

    size_t buf_off = HALF_BUF_SIZE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++)
    {
        dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
        dentry_parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == dentry_mnt || dentry == dentry_parent)
        {
            if (dentry != dentry_mnt)
                break;
            if (mnt != mnt_parent)
            {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
                continue;
            }
            break;
        }

        name_len = (BPF_CORE_READ(dentry, d_name.len)) & (RT_PATH_MAX - 1);
        name = (const unsigned char*)BPF_CORE_READ(dentry, d_name.name);
        name_len = name_len + 1;

        if (name_len > buf_off)
            break;

        size_t new_buf_off = buf_off - name_len;
        ret = bpf_probe_read_kernel_str(&(out_buf->data[LIMIT_HALF(new_buf_off)]), name_len, (const char*)name);
        if (ret < 0)
            return ret;

        if (ret > 1)
        {
            buf_off -= 1;
            buf_off = LIMIT_HALF(buf_off);
            out_buf->data[buf_off] = '/';
            buf_off -= (ret - 1);
            buf_off = LIMIT_HALF(buf_off);
        }
        else
        {
            break;
        }
        dentry = dentry_parent;
    }

    if (buf_off != 0)
    {
        buf_off -= 1;
        buf_off = LIMIT_HALF(buf_off);
        out_buf->data[buf_off] = '/';
    }
    out_buf->data[HALF_BUF_SIZE - 1] = 0;
    *path_str = &out_buf->data[buf_off];
    return HALF_BUF_SIZE - buf_off - 1;
}

statfunc void get_inode_dev(struct inode* inode_ptr, __u64* inode, __u64* dev)
{
    if (!inode_ptr)
        return;
    bpf_probe_read_kernel(inode, sizeof(*inode), &inode_ptr->i_ino);
    struct super_block* sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &inode_ptr->i_sb);
    if (sb)
    {
        __u32 dev32 = 0;
        bpf_probe_read_kernel(&dev32, sizeof(dev32), &sb->s_dev);
        *dev = dev32;
    }
}

statfunc __u32 get_mnt_ns_inum(struct task_struct* task)
{
    if (!task)
        return 0;
    struct nsproxy* nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return 0;
    struct mnt_namespace* mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns)
        return 0;
    return BPF_CORE_READ(mnt_ns, ns.inum);
}

statfunc void submit_event(__u16 event_type, const char* filename, __u64 ino, __u64 dev)
{
    struct rt_file_event* evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt)
    {
        bump_drop_counter();
        return;
    }

    struct task_struct* current_task = (struct task_struct*)bpf_get_current_task();

    evt->abi_major = RT_ABI_MAJOR;
    evt->event_type = event_type;
    evt->flags = 0;
    evt->_reserved0 = 0;
    evt->timestamp_ns = bpf_ktime_get_boot_ns();

    evt->pid = BPF_CORE_READ(current_task, tgid);
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid >> 32;
    evt->gid = uid_gid;

    evt->inode = ino;
    evt->dev = dev;

    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->mnt_ns = get_mnt_ns_inum(current_task);

    evt->dropped = take_drop_counter();
    if (evt->dropped > 0)
    {
        evt->flags |= RT_F_DROPS_BEFORE;
    }

    bpf_probe_read_kernel_str(evt->comm, RT_COMM_MAX, (const char*)BPF_CORE_READ(current_task, comm));
    bpf_probe_read_kernel_str(evt->filename, RT_PATH_MAX, filename);

    evt->ppid = 0;
    struct task_struct* parent_task = BPF_CORE_READ(current_task, real_parent);
    if (parent_task)
    {
        evt->ppid = BPF_CORE_READ(parent_task, tgid);
    }

    bpf_ringbuf_submit(evt, 0);
}

statfunc bool is_regular_file(struct inode* inode)
{
    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
    return (mode & 00170000) == 0100000;
}

/* ---- open/create (kprobe fallback: portable, always compiled) ---- */
SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs* ctx)
{
    struct path* path = (struct path*)PT_REGS_PARM1(ctx);
    struct file* file = (struct file*)PT_REGS_PARM2(ctx);
    if (!path || !file)
        return 0;

    fmode_t f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);
    __u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);
    if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT) && !(f_flags & O_ACCMODE))
        return 0;

    struct dentry* dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);
    if (!dentry)
        return 0;
    struct inode* d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode || !is_regular_file(d_inode))
        return 0;

    struct buffer* buf = bpf_map_lookup_elem(&heaps_map, &(__u32) {0});
    if (!buf)
        return 0;
    unsigned char* full_path = NULL;
    if (get_path_str_from_path(&full_path, path, buf) < 0)
        return 0;

    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);
    submit_event(RT_EV_FILE_OPEN, (const char*)full_path, inode, dev);
    return 0;
}

/* ---- open/create (LSM: namespace-correct bpf_d_path, needs "bpf" active LSM) ---- */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file* file)
{
    fmode_t f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);
    __u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);
    if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT) && !(f_flags & O_ACCMODE))
        return 0;

    struct inode* f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    if (!f_inode || !is_regular_file(f_inode))
        return 0;

    char* full_path = bpf_map_lookup_elem(&dpath_map, &(__u32) {0});
    if (!full_path)
        return 0;
    if (bpf_d_path(&file->f_path, full_path, RT_PATH_MAX) < 0)
        return 0;

    __u64 inode = 0, dev = 0;
    get_inode_dev(f_inode, &inode, &dev);
    submit_event(RT_EV_FILE_OPEN, full_path, inode, dev);
    return 0;
}

/* ---- attribute change (portable across kernel versions via LINUX_KERNEL_VERSION) ---- */
SEC("kprobe/security_inode_setattr")
int kprobe__security_inode_setattr(struct pt_regs* ctx)
{
    struct dentry* dentry;
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 0, 0))
    {
        dentry = (struct dentry*)PT_REGS_PARM1_CORE(ctx);
    }
    else
    {
        dentry = (struct dentry*)PT_REGS_PARM2_CORE(ctx);
    }
    if (!dentry)
        return 0;

    struct inode* d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode || !is_regular_file(d_inode))
        return 0;

    struct super_block* sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb)
        return 0;
    struct mount* mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr)
        return 0;
    struct vfsmount* mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt)
        return 0;

    struct path path = {.dentry = dentry, .mnt = mnt};
    struct buffer* buf = bpf_map_lookup_elem(&heaps_map, &(__u32) {0});
    if (!buf)
        return 0;
    unsigned char* full_path = NULL;
    if (get_path_str_from_path(&full_path, &path, buf) < 0)
        return 0;

    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);
    submit_event(RT_EV_FILE_ATTR, (const char*)full_path, inode, dev);
    return 0;
}

/* ---- unlink (kprobe fallback) ---- */
SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs* ctx)
{
    struct dentry* dentry;
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 12, 0))
    {
        dentry = (struct dentry*)PT_REGS_PARM2_CORE(ctx);
    }
    else
    {
        dentry = (struct dentry*)PT_REGS_PARM3_CORE(ctx);
    }
    if (!dentry)
        return 0;

    struct inode* d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!d_inode || !is_regular_file(d_inode))
        return 0;

    struct super_block* sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb)
        return 0;
    struct mount* mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr)
        return 0;
    struct vfsmount* mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt)
        return 0;

    struct path path = {.dentry = dentry, .mnt = mnt};
    struct buffer* buf = bpf_map_lookup_elem(&heaps_map, &(__u32) {0});
    if (!buf)
        return 0;
    unsigned char* full_path = NULL;
    if (get_path_str_from_path(&full_path, &path, buf) < 0)
        return 0;

    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);
    submit_event(RT_EV_FILE_UNLINK, (const char*)full_path, inode, dev);
    return 0;
}

/* ---- rename (kprobe fallback; reports the destination path, mirrors modern.bpf.c) ----
 *
 * FINDING (validated on a real kernel 7.0.0 VM, not just read): the shadow
 * struct below was WRONG for this kernel and silently produced zero events
 * — kprobe run_cnt confirmed the hook fires, but old_dentry/new_dentry read
 * garbage and failed the safety checks every time. This is the same
 * struct/logic as production's modern.bpf.c, meaning that code has the same
 * latent bug on any kernel with this newer struct renamedata layout: rename
 * events silently stop being detected, with no error surfaced anywhere.
 *
 * Confirmed actual layout via `grep -A10 '^struct renamedata ' vmlinux.h`
 * on the test VM:
 *   struct renamedata {
 *       struct mnt_idmap *mnt_idmap;
 *       struct dentry *old_parent;
 *       struct dentry *old_dentry;
 *       struct dentry *new_parent;
 *       struct dentry *new_dentry;
 *       struct delegated_inode *delegated_inode;
 *       unsigned int flags;
 *   };
 * — one mnt_idmap (not two mnt_userns fields), and old_dir/new_dir are
 * dentries (old_parent/new_parent), not inodes. old_dentry's offset is
 * unchanged (16 bytes in either layout) but new_dentry moved from offset 40
 * (this file's old, wrong assumption) to offset 32 — an 8-byte over-read
 * previously landing on delegated_inode's value instead.
 */
struct renamedata___local
{
    void* mnt_idmap;
    struct dentry* old_parent;
    struct dentry* old_dentry;
    struct dentry* new_parent;
    struct dentry* new_dentry;
};

SEC("kprobe/vfs_rename")
int kprobe__vfs_rename(struct pt_regs* ctx)
{
    struct dentry *old_dentry, *new_dentry;

    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 12, 0))
    {
        old_dentry = (struct dentry*)PT_REGS_PARM2_CORE(ctx);
        new_dentry = (struct dentry*)PT_REGS_PARM4_CORE(ctx);
    }
    else
    {
        struct renamedata___local* rd = (struct renamedata___local*)PT_REGS_PARM1_CORE(ctx);
        if (!rd)
            return 0;
        bpf_probe_read_kernel(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
        bpf_probe_read_kernel(&new_dentry, sizeof(new_dentry), &rd->new_dentry);
    }
    if (!old_dentry || !new_dentry)
        return 0;

    struct inode* d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &old_dentry->d_inode);
    if (!d_inode || !is_regular_file(d_inode))
        return 0;

    __u64 inode = 0, dev = 0;
    get_inode_dev(d_inode, &inode, &dev);

    struct super_block* sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb)
        return 0;
    struct mount* mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr)
        return 0;
    struct vfsmount* mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt)
        return 0;

    struct buffer* buf = bpf_map_lookup_elem(&heaps_map, &(__u32) {0});
    if (!buf)
        return 0;
    struct path new_path = {.dentry = new_dentry, .mnt = mnt};
    unsigned char* full_path = NULL;
    if (get_path_str_from_path(&full_path, &new_path, buf) >= 0)
    {
        submit_event(RT_EV_FILE_RENAME, (const char*)full_path, inode, dev);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

/* Copyright (C) 2015, Wazuh Inc.
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
#define S_IFREG_MASK                    00170000
#define S_IFREG_VAL                     0100000

#define MAX_PERCPU_ARRAY_SIZE           (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE          (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_PATH_SIZE(x)              ((x) & (MAX_PATH_LEN - 1))
#define MAX_PATH_COMPONENTS             320

#define statfunc static inline

/* -------------------------------------------------------------------------
 * Data Structures
 * ------------------------------------------------------------------------- */

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
    __u64 cgroup_id;
    __u32 mntns_ino;
    __u32 pidns_ino;
    __u32 netns_ino;
};

struct buffer {
    u8 data[MAX_PERCPU_ARRAY_SIZE];
};

/* -------------------------------------------------------------------------
 * BPF Maps
 * ------------------------------------------------------------------------- */

// Ring buffer for delivering events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} rb SEC(".maps");

// Per-CPU scratchpad for reverse path reconstruction
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

// Per-CPU buffer for bpf_d_path output
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, char[MAX_PATH_LEN]);
    __uint(max_entries, 1);
} full_path_map SEC(".maps");

// Per-CPU buffer for task CWD resolution
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} cwd_heap SEC(".maps");

// Kernel version check for compile-once / run-everywhere relocations
extern int LINUX_KERNEL_VERSION __kconfig;

/* -------------------------------------------------------------------------
 * CO-RE Shadows for Cross-Kernel Portability
 * ------------------------------------------------------------------------- */

// Shadow for task_struct.loginuid (handles kernels built without CONFIG_AUDIT)
struct task_struct___local {
    kuid_t loginuid;
};

// Shadow for struct renamedata (vfs_rename >= 5.12)
struct renamedata___local {
    void          *old_mnt_userns;
    struct inode  *old_dir;
    struct dentry *old_dentry;
    void          *new_mnt_userns;
    struct inode  *new_dir;
    struct dentry *new_dentry;
};

/* -------------------------------------------------------------------------
 * Helper Functions (Path Reconstruction & Metadata Extraction)
 * ------------------------------------------------------------------------- */

statfunc bool is_regular_file(struct inode *inode_ptr) {
    if (!inode_ptr) return false;
    __u32 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &inode_ptr->i_mode);
    return (mode & S_IFREG_MASK) == S_IFREG_VAL;
}

statfunc void extract_inode_dev(struct inode *inode_ptr, __u64 *inode, __u64 *dev) {
    if (!inode_ptr) return;

    bpf_probe_read_kernel(inode, sizeof(*inode), &inode_ptr->i_ino);

    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &inode_ptr->i_sb);
    if (sb) {
        __u32 dev32 = 0;
        bpf_probe_read_kernel(&dev32, sizeof(dev32), &sb->s_dev);
        *dev = dev32;
    }
}

statfunc long concat_path_strings(unsigned char **full_path,
                                  const char *dir_path,
                                  const char *filename,
                                  struct buffer *out_buf)
{
    size_t buf_off = 0;
    size_t max_len = HALF_PERCPU_ARRAY_SIZE;

    long ret = bpf_probe_read_kernel_str(&out_buf->data[buf_off], max_len, dir_path);
    if (ret <= 0) return -1;
    size_t dir_path_len = ret;

    buf_off = dir_path_len - 1;

    /* Probe the character before the terminator to avoid a doubled separator.
     * The index goes through a volatile plus the buffer mask: clang would
     * otherwise fold it into a raw "-1" offset the verifier rejects with
     * "R2 min value is negative", which drops every bpf_d_path variant. */
    volatile size_t separator_off = buf_off - 1;
    if (buf_off == 0 || out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(separator_off)] != '/') {
        out_buf->data[buf_off] = '/';
        buf_off++;
    }

    max_len = HALF_PERCPU_ARRAY_SIZE - buf_off;
    ret = bpf_probe_read_kernel_str(&out_buf->data[buf_off], max_len, filename);
    if (ret <= 0) return -1;

    *full_path = &out_buf->data[0];
    return (dir_path_len - 1) + (ret - 1);
}

statfunc long resolve_dentry_path(unsigned char **path_str,
                                  const struct path *path,
                                  struct buffer *out_buf)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    struct mount *mnt = container_of(vfsmnt, struct mount, mnt);
    struct mount *mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

    size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
        struct dentry *dentry_parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == dentry_mnt || dentry == dentry_parent) {
            if (dentry != dentry_mnt) break;
            if (mnt != mnt_parent) {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
                continue;
            }
            break;
        }

        size_t name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len)) + 1;
        const unsigned char *name = (const unsigned char *)BPF_CORE_READ(dentry, d_name.name);

        if (name_len > buf_off) break;

        volatile size_t new_buf_off = buf_off - name_len;
        long ret = bpf_probe_read_kernel_str(
            &(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buf_off)]),
            name_len, (const char *)name);
        if (ret <= 0) return ret;

        if (ret > 1) {
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off - 1);
            out_buf->data[buf_off] = '/';
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off - (ret - 1));
        } else {
            break;
        }
        dentry = dentry_parent;
    }

    if (buf_off != 0) {
        buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off - 1);
        out_buf->data[buf_off] = '/';
    }

    out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
    *path_str = &out_buf->data[buf_off];
    return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

statfunc int resolve_task_cwd(char *dest, int size, struct task_struct *task) {
    if (!task) return -1;
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs) return -1;

    struct path pwd = BPF_CORE_READ(fs, pwd);
    struct buffer *buf = bpf_map_lookup_elem(&cwd_heap, &(u32){0});
    if (!buf) return -1;

    unsigned char *cwd_path = NULL;
    if (resolve_dentry_path(&cwd_path, &pwd, buf) < 0) return -1;

    bpf_probe_read_kernel_str(dest, size, (const char *)cwd_path);
    return 0;
}

statfunc void submit_file_event(const char *filename, __u64 ino, __u64 dev) {
    struct file_event *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) return;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    // Process & user credentials
    evt->pid = BPF_CORE_READ(current_task, tgid);
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid >> 32;
    evt->gid = uid_gid;
    evt->euid = BPF_CORE_READ(current_task, cred, euid.val);

    // Audit Login UID
    struct task_struct___local *task_local = (struct task_struct___local *)current_task;
    kuid_t loginuid = {0};
    if (bpf_core_field_exists(task_local->loginuid)) {
        loginuid = BPF_CORE_READ(task_local, loginuid);
    }
    evt->login_uid = loginuid.val;

    // Process Identity & Strings
    bpf_probe_read_kernel_str(evt->comm, TASK_COMM_LEN, (const char *)BPF_CORE_READ(current_task, comm));
    bpf_probe_read_kernel_str(evt->filename, MAX_PATH_LEN, filename);
    evt->inode = ino;
    evt->dev   = dev;

    evt->cwd[0]         = '\0';
    evt->parent_cwd[0]  = '\0';
    evt->parent_name[0] = '\0';
    resolve_task_cwd(evt->cwd, MAX_PATH_LEN, current_task);

    // Parent task info
    evt->ppid = 0;
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    if (parent_task) {
        evt->ppid = BPF_CORE_READ(parent_task, tgid);
        bpf_probe_read_kernel_str(evt->parent_name, TASK_COMM_LEN, (const char *)BPF_CORE_READ(parent_task, comm));
        resolve_task_cwd(evt->parent_cwd, MAX_PATH_LEN, parent_task);
    }

    // Container correlation keys
    evt->cgroup_id = bpf_get_current_cgroup_id();

    struct nsproxy *nsproxy = BPF_CORE_READ(current_task, nsproxy);
    if (nsproxy) {
        evt->mntns_ino = BPF_CORE_READ(nsproxy, mnt_ns, ns.inum);
        evt->pidns_ino = BPF_CORE_READ(nsproxy, pid_ns_for_children, ns.inum);
        evt->netns_ino = BPF_CORE_READ(nsproxy, net_ns, ns.inum);
    } else {
        evt->mntns_ino = 0;
        evt->pidns_ino = 0;
        evt->netns_ino = 0;
    }

    bpf_ringbuf_submit(evt, 0);
}

/* -------------------------------------------------------------------------
 * SECTION 1: LSM Hooks (BPF LSM enabled kernels)
 * ------------------------------------------------------------------------- */

// --- LSM: file_open ---
static __always_inline bool filter_lsm_file_open(struct file *file, struct inode **out_inode) {
    fmode_t f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);

    __u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);

    if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT) && !(f_flags & O_ACCMODE)) {
        return false;
    }

    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    if (!is_regular_file(f_inode)) {
        return false;
    }

    *out_inode = f_inode;
    return true;
}

SEC("lsm/file_open")
int BPF_PROG(file_open_dpath, struct file *file) {
    struct inode *f_inode = NULL;
    if (!filter_lsm_file_open(file, &f_inode)) return 0;

    char *full_path = bpf_map_lookup_elem(&full_path_map, &(u32){0});
    if (!full_path || bpf_d_path(&file->f_path, full_path, MAX_PATH_LEN) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(f_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open_walk, struct file *file) {
    struct inode *f_inode = NULL;
    if (!filter_lsm_file_open(file, &f_inode)) return 0;

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, &file->f_path, string_buf) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(f_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

// --- LSM: path_unlink ---
static __always_inline bool filter_lsm_unlink(struct dentry *dentry, struct inode **out_inode) {
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!is_regular_file(d_inode)) return false;

    *out_inode = d_inode;
    return true;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink_dpath, struct path *path, struct dentry *dentry) {
    struct inode *d_inode = NULL;
    if (!filter_lsm_unlink(dentry, &d_inode)) return 0;

    char *dir_path = bpf_map_lookup_elem(&full_path_map, &(u32){0});
    if (!dir_path || bpf_d_path(path, dir_path, MAX_PATH_LEN) < 0) return 0;

    const char *file_name_ptr = NULL;
    bpf_probe_read_kernel(&file_name_ptr, sizeof(file_name_ptr), &dentry->d_name.name);
    if (!file_name_ptr) return 0;

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (concat_path_strings(&full_path, dir_path, file_name_ptr, string_buf) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(d_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink_walk, struct path *path, struct dentry *dentry) {
    struct inode *d_inode = NULL;
    if (!filter_lsm_unlink(dentry, &d_inode)) return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &path->mnt);
    if (!mnt) return 0;

    struct path file_path = { .dentry = dentry, .mnt = mnt };
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, &file_path, string_buf) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(d_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

// --- LSM: path_rename ---
static __always_inline bool filter_lsm_rename(struct dentry *old_dentry, __u64 *inode, __u64 *dev) {
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &old_dentry->d_inode);
    if (!is_regular_file(d_inode)) return false;

    extract_inode_dev(d_inode, inode, dev);
    return true;
}

SEC("lsm/path_rename")
int BPF_PROG(path_rename_dpath, struct path *old_dir, struct dentry *old_dentry,
             struct path *new_dir, struct dentry *new_dentry, unsigned int flags) {
    __u64 inode = 0, dev = 0;
    if (!filter_lsm_rename(old_dentry, &inode, &dev)) return 0;

    char *dir_path = bpf_map_lookup_elem(&full_path_map, &(u32){0});
    if (!dir_path || bpf_d_path(new_dir, dir_path, MAX_PATH_LEN) < 0) return 0;

    const char *file_name_ptr = NULL;
    bpf_probe_read_kernel(&file_name_ptr, sizeof(file_name_ptr), &new_dentry->d_name.name);
    if (!file_name_ptr) return 0;

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (concat_path_strings(&full_path, dir_path, file_name_ptr, string_buf) >= 0) {
        submit_file_event((const char *)full_path, inode, dev);
    }
    return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(path_rename_walk, struct path *old_dir, struct dentry *old_dentry,
             struct path *new_dir, struct dentry *new_dentry, unsigned int flags) {
    __u64 inode = 0, dev = 0;
    if (!filter_lsm_rename(old_dentry, &inode, &dev)) return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &new_dir->mnt);
    if (!mnt) return 0;

    struct path new_path = { .dentry = new_dentry, .mnt = mnt };
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, &new_path, string_buf) >= 0) {
        submit_file_event((const char *)full_path, inode, dev);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * SECTION 2: kprobe Hooks (Fallback for non-LSM kernels)
 * ------------------------------------------------------------------------- */

// --- kprobe: vfs_open ---
SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs *ctx) {
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    struct file *file = (struct file *)PT_REGS_PARM2(ctx);
    if (!path || !file) return 0;

    fmode_t f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);

    __u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);

    if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT)) {
        return 0;
    }

    struct dentry *dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);
    if (!dentry) return 0;

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!is_regular_file(d_inode)) return 0;

    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, path, string_buf) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(d_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

// --- kprobe: security_inode_setattr ---
SEC("kprobe/security_inode_setattr")
int kprobe__security_inode_setattr(struct pt_regs *ctx) {
    struct dentry *dentry = (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 0, 0))
        ? (struct dentry *)PT_REGS_PARM1_CORE(ctx)
        : (struct dentry *)PT_REGS_PARM2_CORE(ctx);

    if (!dentry) return 0;

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!is_regular_file(d_inode)) return 0;

    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb) return 0;

    struct mount *mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr) return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt) return 0;

    struct path path = { .dentry = dentry, .mnt = mnt };
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, &path, string_buf) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(d_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

// --- kprobe: vfs_unlink ---
SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs *ctx) {
    struct dentry *dentry = (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 12, 0))
        ? (struct dentry *)PT_REGS_PARM2_CORE(ctx)
        : (struct dentry *)PT_REGS_PARM3_CORE(ctx);

    if (!dentry) return 0;

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (!is_regular_file(d_inode)) return 0;

    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb) return 0;

    struct mount *mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr) return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt) return 0;

    struct path path = { .dentry = dentry, .mnt = mnt };
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, &path, string_buf) < 0) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(d_inode, &inode, &dev);
    submit_file_event((const char *)full_path, inode, dev);
    return 0;
}

// --- kprobe: vfs_rename ---
SEC("kprobe/vfs_rename")
int kprobe__vfs_rename(struct pt_regs *ctx) {
    struct dentry *old_dentry = NULL;
    struct dentry *new_dentry = NULL;

    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 12, 0)) {
        old_dentry = (struct dentry *)PT_REGS_PARM2_CORE(ctx);
        new_dentry = (struct dentry *)PT_REGS_PARM4_CORE(ctx);
    } else {
        struct renamedata___local *rd = (struct renamedata___local *)PT_REGS_PARM1_CORE(ctx);
        if (!rd) return 0;
        bpf_probe_read_kernel(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
        bpf_probe_read_kernel(&new_dentry, sizeof(new_dentry), &rd->new_dentry);
    }

    if (!old_dentry || !new_dentry) return 0;

    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &old_dentry->d_inode);
    if (!is_regular_file(d_inode)) return 0;

    __u64 inode = 0, dev = 0;
    extract_inode_dev(d_inode, &inode, &dev);

    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &d_inode->i_sb);
    if (!sb) return 0;

    struct mount *mnt_ptr = NULL;
    bpf_probe_read_kernel(&mnt_ptr, sizeof(mnt_ptr), &sb->s_fs_info);
    if (!mnt_ptr) return 0;

    struct vfsmount *mnt = NULL;
    bpf_probe_read_kernel(&mnt, sizeof(mnt), &mnt_ptr->mnt);
    if (!mnt) return 0;

    struct path new_path = { .dentry = new_dentry, .mnt = mnt };
    struct buffer *string_buf = bpf_map_lookup_elem(&heaps_map, &(u32){0});
    if (!string_buf) return 0;

    u8 *full_path = NULL;
    if (resolve_dentry_path(&full_path, &new_path, string_buf) >= 0) {
        submit_file_event((const char *)full_path, inode, dev);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

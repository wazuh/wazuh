/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ebpf_loader.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <sstream>

namespace wazuh::ebpf {

namespace {

constexpr const char* DEFAULT_BPF_OBJ_PATH = "lib/modern.bpf.o";
constexpr const char* KERNEL_OSRELEASE_FILE = "/proc/sys/kernel/osrelease";
constexpr const char* LSM_LIST_FILE = "/sys/kernel/security/lsm";
constexpr const char* RING_BUFFER_MAP = "rb";
constexpr int MIN_KERNEL_MAJOR = 5;
constexpr int MIN_KERNEL_MINOR = 8;
constexpr size_t MAX_PATH_LEN = 4096;
constexpr size_t TASK_COMM_LEN = 32;

/// Flat kernel record emitted by struct file_event in bpf/modern.bpf.c.
struct RawFileEvent {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t euid;
    uint32_t login_uid;
    uint64_t inode;
    uint64_t dev;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char cwd[MAX_PATH_LEN];
    char parent_cwd[MAX_PATH_LEN];
    char parent_name[TASK_COMM_LEN];
    uint64_t cgroup_id;
    uint32_t mntns_ino;
    uint32_t pidns_ino;
    uint32_t netns_ino;
};

/// Records without the correlation keys still decode: the precompiled object
/// shipped with the dependencies predates them.
constexpr size_t RAW_EVENT_MIN_SIZE = offsetof(RawFileEvent, cgroup_id);

inline bool bpfLinkIsError(const struct bpf_link* link) {
    return !link || reinterpret_cast<uintptr_t>(link) >= static_cast<uintptr_t>(-4095UL);
}

/// Kernel strings are not guaranteed to be NUL terminated.
inline std::string toString(const char* field, size_t capacity) {
    return std::string(field, strnlen(field, capacity));
}

} // namespace

EbpfLoader::~EbpfLoader() {
    EbpfLoader::close();
}

bool EbpfLoader::isKernelSupported() {
    std::ifstream file(KERNEL_OSRELEASE_FILE);
    if (!file.is_open()) {
        return false;
    }

    std::string release;
    file >> release;

    int major = 0;
    int minor = 0;
    char dot = 0;
    std::istringstream stream(release);
    if (!(stream >> major >> dot >> minor)) {
        return false;
    }

    return major > MIN_KERNEL_MAJOR || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR);
}

bool EbpfLoader::isBpfLsmActive() {
    std::ifstream file(LSM_LIST_FILE);
    if (!file.is_open()) {
        return false;
    }

    std::string lsm_list;
    if (!std::getline(file, lsm_list)) {
        return false;
    }

    return ("," + lsm_list + ",").find(",bpf,") != std::string::npos;
}

bool EbpfLoader::load(EventClass event_class, const std::string& bpf_obj_path) {
    // ponytail: every program in the object belongs to FILE. When exec/network
    // hooks land, map each program to its class by name prefix and filter here.
    if (event_class != EventClass::FILE) {
        return false;
    }

    if (!isKernelSupported()) {
        return false;
    }

    const std::string obj_path = bpf_obj_path.empty() ? DEFAULT_BPF_OBJ_PATH : bpf_obj_path;
    return openAndLoad(obj_path) && attach();
}

void EbpfLoader::selectPrograms(bool prefer_dpath) {
    struct bpf_program* prog = nullptr;
    bpf_object__for_each_program(prog, m_bpf_obj) {
        const char* sec = bpf_program__section_name(prog);
        const char* name = bpf_program__name(prog);
        if (!sec) {
            continue;
        }

        const bool is_lsm = (strncmp(sec, "lsm/", 4) == 0);
        const bool is_create_or_unlink_kprobe =
            (strncmp(sec, "kprobe/", 7) == 0) &&
            (strstr(sec, "vfs_open") != nullptr || strstr(sec, "vfs_unlink") != nullptr ||
             strstr(sec, "vfs_rename") != nullptr);
        const bool is_dpath_variant = name && strstr(name, "_dpath") != nullptr;
        const bool is_walk_variant = name && strstr(name, "_walk") != nullptr;

        // With LSM available the kprobe fallbacks for create/unlink/rename are
        // redundant, and only one of the dpath/walk variants must be loaded.
        const bool keep =
            !(m_lsm_active ? (is_create_or_unlink_kprobe ||
                              (is_lsm && (prefer_dpath ? is_walk_variant : is_dpath_variant)))
                           : is_lsm);

        bpf_program__set_autoload(prog, keep);
    }
}

bool EbpfLoader::openAndLoad(const std::string& bpf_obj_path) {
    close();

    m_lsm_active = isBpfLsmActive();
    bool prefer_dpath = m_lsm_active;

    while (true) {
        m_bpf_obj = bpf_object__open_file(bpf_obj_path.c_str(), nullptr);
        if (!m_bpf_obj) {
            return false;
        }

        selectPrograms(prefer_dpath);

        if (bpf_object__load(m_bpf_obj) == 0) {
            return true;
        }

        bpf_object__close(m_bpf_obj);
        m_bpf_obj = nullptr;

        // Retry once with the path walker when bpf_d_path is not usable.
        if (m_lsm_active && prefer_dpath) {
            prefer_dpath = false;
            continue;
        }

        return false;
    }
}

bool EbpfLoader::attach() {
    if (!m_bpf_obj) {
        return false;
    }

    struct bpf_program* prog = nullptr;
    bpf_object__for_each_program(prog, m_bpf_obj) {
        if (!bpf_program__autoload(prog)) {
            continue;
        }

        struct bpf_link* link = bpf_program__attach(prog);
        if (bpfLinkIsError(link)) {
            close();
            return false;
        }
        m_links.push_back(link);
    }

    return true;
}

int EbpfLoader::onRingSample(void* ctx, void* data, size_t size) {
    auto* self = static_cast<EbpfLoader*>(ctx);
    if (!self || !self->m_callback || !data || size < RAW_EVENT_MIN_SIZE) {
        return 0;
    }

    const auto* raw = static_cast<const RawFileEvent*>(data);

    FileEvent event;
    event.identity.pid = raw->pid;
    event.identity.ppid = raw->ppid;
    event.identity.uid = raw->uid;
    event.identity.gid = raw->gid;
    event.identity.euid = raw->euid;
    event.identity.login_uid = raw->login_uid;
    event.identity.comm = toString(raw->comm, sizeof(raw->comm));
    event.identity.parent_comm = toString(raw->parent_name, sizeof(raw->parent_name));
    event.identity.cwd = toString(raw->cwd, sizeof(raw->cwd));
    event.inode = raw->inode;
    event.dev = raw->dev;
    event.path = toString(raw->filename, sizeof(raw->filename));

    if (size >= sizeof(RawFileEvent)) {
        event.correlation.cgroup_id = raw->cgroup_id;
        event.correlation.mntns_ino = raw->mntns_ino;
        event.correlation.pidns_ino = raw->pidns_ino;
        event.correlation.netns_ino = raw->netns_ino;
    }

    (*self->m_callback)(event);
    return 0;
}

bool EbpfLoader::poll(const FileEventCallback& callback, int timeout_ms) {
    if (!m_bpf_obj) {
        return false;
    }

    if (!m_ring_buf) {
        const int map_fd = bpf_object__find_map_fd_by_name(m_bpf_obj, RING_BUFFER_MAP);
        if (map_fd < 0) {
            return false;
        }

        m_ring_buf = ring_buffer__new(map_fd, &EbpfLoader::onRingSample, this, nullptr);
        if (!m_ring_buf) {
            return false;
        }
    }

    m_callback = &callback;
    const int ret = ring_buffer__poll(m_ring_buf, timeout_ms);
    m_callback = nullptr;

    return ret >= 0;
}

void EbpfLoader::close() {
    if (m_ring_buf) {
        ring_buffer__free(m_ring_buf);
        m_ring_buf = nullptr;
    }

    for (auto* link : m_links) {
        if (link && !bpfLinkIsError(link)) {
            bpf_link__destroy(link);
        }
    }
    m_links.clear();

    if (m_bpf_obj) {
        bpf_object__close(m_bpf_obj);
        m_bpf_obj = nullptr;
    }
}

} // namespace wazuh::ebpf

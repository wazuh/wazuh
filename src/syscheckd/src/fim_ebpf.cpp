/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <pwd.h>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "bounded_queue.hpp"
#include "ebpf_loader.hpp"

extern "C" {
#include "shared.h"
#include "syscheck.h"
#include "syscheck_op.h"
#include "debug_op.h"
#include "list_op.h"
#include "fim_ebpf.h"

int ebpf_kernel_queue_full_reported = 0;
}

using wazuh::ebpf::EbpfLoader;
using wazuh::ebpf::EventClass;
using wazuh::ebpf::FileEvent;
using wazuh::ebpf::FileEventCallback;

namespace {

constexpr const char* EBPF_HC_FILE = "tmp/ebpf_hc";
constexpr int RING_POLL_MS = 500;
constexpr int QUEUE_POP_MS = 500;
constexpr int HC_ACTION_TIMEOUT_S = 10;
constexpr size_t DETAIL_SIZE = 4200;

template<typename T>
char* num_to_str(T num) {
    return strdup(std::to_string(num).c_str());
}

int get_login_gid(unsigned int uid) {
    struct passwd pwd {};
    struct passwd* result = nullptr;
    char buf[16384];
    if (getpwuid_r(uid, &pwd, buf, sizeof(buf), &result) != 0 || result == nullptr) {
        return -1;
    }
    return static_cast<int>(pwd.pw_gid);
}

/// Directories configured with whodata; events outside them are dropped.
std::vector<std::string> monitored_prefixes() {
    std::vector<std::string> prefixes;

    if (!syscheck.directories) {
        return prefixes;
    }

    w_rwlock_rdlock(&syscheck.directories_lock);
    OSListNode* node_it = nullptr;
    OSList_foreach(node_it, syscheck.directories) {
        auto* dir = static_cast<directory_t*>(node_it->data);
        if (dir && (dir->options & WHODATA_ACTIVE)) {
            prefixes.emplace_back(dir->path);
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);

    return prefixes;
}

void deliver_to_fim(const FileEvent& event) {
    auto* w_evt = static_cast<whodata_evt*>(calloc(1, sizeof(whodata_evt)));
    if (!w_evt) {
        return;
    }

    w_evt->path = strdup(event.path.c_str());
    w_evt->process_name = strdup(event.identity.comm.c_str());
    w_evt->user_id = num_to_str(event.identity.uid);
    w_evt->user_name = get_user(static_cast<int>(event.identity.uid));
    w_evt->group_id = num_to_str(event.identity.gid);
    w_evt->group_name = get_group(static_cast<int>(event.identity.gid));
    w_evt->effective_uid = num_to_str(event.identity.euid);
    w_evt->effective_name = get_user(static_cast<int>(event.identity.euid));
    w_evt->audit_uid = num_to_str(event.identity.login_uid);
    w_evt->audit_name = get_user(static_cast<int>(event.identity.login_uid));

    const int audit_gid_val = get_login_gid(event.identity.login_uid);
    if (audit_gid_val >= 0) {
        w_evt->audit_gid = num_to_str(static_cast<unsigned int>(audit_gid_val));
        w_evt->audit_group_name = get_group(audit_gid_val);
    }

    w_evt->inode = num_to_str(event.inode);
    w_evt->dev = num_to_str(event.dev);
    w_evt->process_id = event.identity.pid;
    w_evt->ppid = event.identity.ppid;
    w_evt->cwd = strdup(event.identity.cwd.c_str());
    w_evt->parent_cwd = strdup(event.identity.parent_comm.c_str());
    w_evt->parent_name = strdup(event.identity.parent_comm.c_str());

    fim_whodata_event(w_evt);
    free_whodata_event(w_evt);
}

/* -------------------------------------------------------------------------
 * Healthcheck: exercises the whole path (kernel hook to userspace event) on a
 * temporary file, so a host where eBPF loads but reports nothing falls back to
 * audit instead of running blind.
 * ------------------------------------------------------------------------- */

using HealthcheckOperation = bool (*)(const char* file_path, char* detail, size_t detail_size);

bool create_healthcheck_file(const char* file_path, char* detail, size_t detail_size) {
    std::ofstream file(file_path);
    if (!file.is_open()) {
        merror(FIM_ERROR_EBPF_HEALTHCHECK_FILE, file_path);
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_CREATE_DETAIL);
        return false;
    }

    file << "Testing eBPF healthcheck\n";
    return true;
}

bool modify_healthcheck_file_content(const char* file_path, char* detail, size_t detail_size) {
    std::ofstream file(file_path, std::ios::app);
    if (!file.is_open()) {
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_CONTENT_DETAIL);
        return false;
    }

    file << "Updating eBPF healthcheck\n";
    return true;
}

bool modify_healthcheck_file_metadata(const char* file_path, char* detail, size_t detail_size) {
    struct stat file_stat = {};

    const int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        snprintf(detail, detail_size, FIM_EBPF_HEALTHCHECK_STAT_DETAIL, file_path, strerror(errno));
        return false;
    }

    if (fstat(fd, &file_stat) != 0) {
        const int saved_errno = errno;
        close(fd);
        snprintf(detail, detail_size, FIM_EBPF_HEALTHCHECK_STAT_DETAIL, file_path, strerror(saved_errno));
        return false;
    }

    const mode_t new_mode = ((file_stat.st_mode & 0777) ^ S_IXUSR) & 0777;
    if (fchmod(fd, new_mode) != 0) {
        const int saved_errno = errno;
        close(fd);
        snprintf(detail, detail_size, FIM_EBPF_HEALTHCHECK_CHMOD_DETAIL, file_path, strerror(saved_errno));
        return false;
    }

    close(fd);
    return true;
}

bool delete_healthcheck_file(const char* file_path, char* detail, size_t detail_size) {
    if (std::remove(file_path) != 0) {
        merror(FIM_ERROR_EBPF_HEALTHCHECK_FILE_DEL, file_path);
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_DELETE_DETAIL);
        return false;
    }

    return true;
}

/// Drains the ring until the event for the healthcheck file shows up.
bool wait_for_healthcheck_event(EbpfLoader& loader, char* detail, size_t detail_size) {
    bool event_received = false;
    const FileEventCallback on_event = [&event_received](const FileEvent& event) {
        if (event.path.find(EBPF_HC_FILE) != std::string::npos) {
            event_received = true;
        }
    };

    const time_t start_time = time(nullptr);

    while (!event_received) {
        if (!loader.poll(on_event, RING_POLL_MS)) {
            merror(FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_EVENT_CONSUME_DETAIL);
            return false;
        }

        if (time(nullptr) - start_time >= HC_ACTION_TIMEOUT_S) {
            snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_EVENT_TIMEOUT_DETAIL);
            return false;
        }
    }

    return true;
}

bool run_healthcheck_action(EbpfLoader& loader,
                            const char* action,
                            const char* file_path,
                            HealthcheckOperation operation,
                            bool enabled) {
    char detail[DETAIL_SIZE] = {0};

    if (!enabled) {
        merror(FIM_ERROR_EBPF_HEALTHCHECK_ACTION_SKIPPED, action, FIM_EBPF_HEALTHCHECK_SKIP_DETAIL);
        return false;
    }

    if (!operation(file_path, detail, sizeof(detail)) ||
        !wait_for_healthcheck_event(loader, detail, sizeof(detail))) {
        merror(FIM_ERROR_EBPF_HEALTHCHECK_ACTION_FAILED, action, detail);
        return false;
    }

    minfo(FIM_EBPF_HEALTHCHECK_ACTION_SUCCESS, action);
    return true;
}

bool run_healthcheck() {
    EbpfLoader loader;

    if (!loader.load(EventClass::FILE)) {
        return false;
    }

    char hc_path[PATH_MAX] = {0};
    abspath(EBPF_HC_FILE, hc_path, sizeof(hc_path));

    if (std::remove(hc_path) == 0) {
        mdebug2(FIM_EBPF_HEALTHCHECK_CLEANUP);
    }

    const bool file_created = run_healthcheck_action(loader, "create file", hc_path, create_healthcheck_file, true);
    bool failed = !file_created;

    failed |= !run_healthcheck_action(
        loader, "modify content", hc_path, modify_healthcheck_file_content, file_created);
    failed |= !run_healthcheck_action(
        loader, "modify metadata", hc_path, modify_healthcheck_file_metadata, file_created);
    failed |= !run_healthcheck_action(loader, "delete file", hc_path, delete_healthcheck_file, file_created);

    if (std::remove(hc_path) != 0 && errno != ENOENT) {
        merror(FIM_ERROR_EBPF_HEALTHCHECK_FILE_DEL, hc_path);
    }

    return !failed;
}

} // namespace

extern "C" {

void check_ebpf_availability(void) {
#if defined(__linux__) && defined(ENABLE_AUDIT)
    minfo(FIM_EBPF_INIT);

    if (!EbpfLoader::isKernelSupported()) {
        merror(FIM_ERROR_EBPF_INVALID_KERNEL);
        mwarn(FIM_ERROR_EBPF_HEALTHCHECK);
        syscheck.whodata_provider = AUDIT_PROVIDER;
        return;
    }

    if (EbpfLoader::isBpfLsmActive()) {
        minfo(FIM_EBPF_LSM_ACTIVE);
    } else {
        minfo(FIM_EBPF_LSM_INACTIVE);
    }

    if (!run_healthcheck()) {
        mwarn(FIM_ERROR_EBPF_HEALTHCHECK);
        syscheck.whodata_provider = AUDIT_PROVIDER;
        return;
    }

    minfo(FIM_EBPF_HEALTHCHECK_SUCCESS);
#endif
}

void* ebpf_whodata(void* arg) {
    (void)arg;
#if defined(__linux__) && defined(ENABLE_AUDIT)
    EbpfLoader loader;

    if (!loader.load(EventClass::FILE)) {
        merror(FIM_ERROR_EBPF_LIB_LOAD);
        return nullptr;
    }

    const auto prefixes = monitored_prefixes();
    wazuh::ebpf::BoundedQueue<FileEvent> queue(syscheck.queue_size);
    std::atomic<bool> consuming {true};

    // FIM does database work per event, so it runs on its own thread: blocking
    // here would stall the ring buffer and make the kernel drop events.
    std::thread consumer([&queue, &consuming]() {
        FileEvent event;
        while (consuming.load(std::memory_order_relaxed)) {
            if (queue.pop(event, QUEUE_POP_MS)) {
                deliver_to_fim(event);
            }
        }
    });

    const FileEventCallback on_event = [&prefixes, &queue](const FileEvent& event) {
        if (!wazuh::ebpf::matchesAnyPrefix(event.path, prefixes)) {
            return;
        }

        if (!queue.push(FileEvent(event)) && !ebpf_kernel_queue_full_reported) {
            mwarn(FIM_FULL_EBPF_KERNEL_QUEUE);
            ebpf_kernel_queue_full_reported = 1;
        }
    };

    while (!fim_shutdown_process_on()) {
        if (!loader.poll(on_event, RING_POLL_MS)) {
            merror(FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            break;
        }
    }

    consuming = false;
    consumer.join();
#endif
    return nullptr;
}

} // extern "C"

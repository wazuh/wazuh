/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <atomic>
#include <cstring>
#include <pwd.h>
#include <string>
#include <vector>

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

namespace {

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

void deliver_to_fim(const wazuh::ebpf::FileEvent& event) {
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

} // namespace

extern "C" {

void check_ebpf_availability(void) {
#if defined(__linux__) && defined(ENABLE_AUDIT)
    minfo(FIM_EBPF_INIT);

    if (!wazuh::ebpf::EbpfLoader::isKernelSupported()) {
        mwarn(FIM_ERROR_EBPF_HEALTHCHECK);
        syscheck.whodata_provider = AUDIT_PROVIDER;
        return;
    }

    if (wazuh::ebpf::EbpfLoader::isBpfLsmActive()) {
        minfo(FIM_EBPF_LSM_ACTIVE);
    } else {
        minfo(FIM_EBPF_LSM_INACTIVE);
    }
#endif
}

void* ebpf_whodata(void* arg) {
    (void)arg;
#if defined(__linux__) && defined(ENABLE_AUDIT)
    wazuh::ebpf::EbpfLoader loader;

    if (!loader.load(wazuh::ebpf::EventClass::FILE)) {
        merror(FIM_ERROR_EBPF_LIB_LOAD);
        return nullptr;
    }

    const auto prefixes = monitored_prefixes();
    const wazuh::ebpf::FileEventCallback on_event = [&prefixes](const wazuh::ebpf::FileEvent& event) {
        if (wazuh::ebpf::matchesAnyPrefix(event.path, prefixes)) {
            deliver_to_fim(event);
        }
    };

    while (!fim_shutdown_process_on()) {
        if (!loader.poll(on_event)) {
            merror(FIM_ERROR_EBPF_RINGBUFF_NEW);
            break;
        }
    }
#endif
    return nullptr;
}

} // extern "C"

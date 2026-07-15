/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * FIM-side wiring for the container baseline module (spike #37532). See
 * container_baseline_fim.h for the rationale; this file only translates
 * syscheck.k8s_directories into the library's plain-C row descriptors and
 * forwards each produced row into the existing persist_syscheck_msg() path.
 */

#include "container_baseline_fim.h"

#include "container_baseline.h"

// Pre-include <atomic> so that shared.h's "#ifdef __cplusplus #include <atomic>"
// block becomes a no-op inside the extern "C" wrapper below, avoiding the
// "template with C linkage" error that would otherwise occur.
#include <atomic>

extern "C" {
#include "shared.h"
#include "syscheck.h"
}

#include <vector>

namespace {

void FimBaselineSink(const char* id, int operation, const char* index, const char* json, uint64_t version, void* user_data)
{
    (void)user_data;

    cJSON* msg = cJSON_Parse(json);
    if (msg == nullptr) {
        mdebug1("Container FIM baseline: dropping row '%s' — failed to re-parse its own JSON.", id);
        return;
    }

    persist_syscheck_msg(id, static_cast<Operation_t>(operation), index, msg, version);
    cJSON_Delete(msg);
}

} // namespace

extern "C" void fim_run_k8s_container_baseline(void)
{
    if (syscheck.k8s_directories == NULL) {
        return; // No <directories type="kubernetes"> configured — nothing to baseline.
    }
    if (!syscheck.enable_synchronization) {
        mdebug2("Container FIM baseline: FIM synchronization is disabled, skipping.");
        return;
    }

    // Unlocked read of k8s_directories, matching check_ebpf_availability()'s own
    // access pattern for this same list (src/syscheckd/src/syscheck.c) — the
    // list is populated once at config parse time and this call site runs
    // once, synchronously, during that same startup sequence.
    std::vector<cb_monitored_path_t> paths;
    OSListNode* it;
    OSList_foreach(it, syscheck.k8s_directories)
    {
        const k8s_monitored_path_t* p = static_cast<const k8s_monitored_path_t*>(it->data);
        if (p == NULL || p->internal_path == NULL) {
            continue;
        }

        cb_monitored_path_t cp;
        cp.internal_path    = p->internal_path;
        cp.recursion_level  = p->recursion_level;
        cp.max_files        = 20000;      // NFR3-style hard cap; see rootfs_file_walker.hpp.
        cp.max_hash_bytes   = 104857600;  // 100 MiB per file.
        paths.push_back(cp);
    }

    if (paths.empty()) {
        return;
    }

    const int baselined =
        cbaseline_run_fim(CB_DEFAULT_CONNECTOR_SOCKET_PATH, paths.data(), static_cast<int>(paths.size()),
                          FimBaselineSink, NULL);

    minfo("Container FIM baseline: scanned %d container(s) across %zu monitored path(s).", baselined, paths.size());
}

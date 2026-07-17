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
 * syscheck.directories into the library's plain-C row descriptors and
 * forwards each produced row into the existing persist_syscheck_msg() path.
 */

#include "container_baseline_fim.h"

#include "container_baseline.h"
#include "container_baseline_fim_bridge.h"

namespace {

void FimBaselineSink(const char* id, int operation, const char* index, const char* json, uint64_t version, void* user_data)
{
    (void)user_data;
    fim_persist_baseline_row(id, operation, index, json, version);
}

} // namespace

extern "C" void fim_run_k8s_container_baseline(void)
{
    cb_monitored_path_t* paths = NULL;
    size_t path_count = 0;

    if (fim_collect_k8s_monitored_paths(&paths, &path_count) != 0) {
        return;
    }
    if (paths == NULL || path_count == 0U) {
        return;
    }

    if (!fim_k8s_container_baseline_available(CB_DEFAULT_CONNECTOR_SOCKET_PATH)) {
        fim_free_k8s_monitored_paths(paths);
        return;
    }

    const int baselined = cbaseline_run_fim(CB_DEFAULT_CONNECTOR_SOCKET_PATH, paths, static_cast<int>(path_count), FimBaselineSink, NULL);
    fim_free_k8s_monitored_paths(paths);
    fim_report_k8s_container_baseline_result(baselined);
}

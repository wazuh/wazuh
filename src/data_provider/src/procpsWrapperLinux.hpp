/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#pragma once

#include <functional>

extern "C"
{
#include "readproc.h"
}

namespace ProcpsWrapper
{
    using ProcCallback = std::function<void(const proc_t*)>;

    // Serializes a full openproc/readproc/closeproc iteration with a
    // process-wide mutex. The vendored procps 2.8.3 keeps scratch buffers as
    // `static` inside simple_readproc/simple_readtask/file2str/get_proc_stats,
    // so concurrent iterations from different threads corrupt each other and
    // can crash inside stat2proc (see issue #36166).
    void scanProcesses(int flags, const ProcCallback& callback);
}

/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESSES_WRAPPER_IMPL_MAC_H
#define _PROCESSES_WRAPPER_IMPL_MAC_H

#include <algorithm>
#include <system_error>
#include <sys/types.h>
#include <vector>
#include "osPrimitivesInterfaceMac.h"

// Shared by getProcessesSocketFD() and SysInfo::getProcessesInfo(): both need the
// full pid list, and proc_listallpids() takes the buffer size in bytes, not the
// pid count, so the byte-size math (and the fix for it) must not be duplicated.
inline std::vector<pid_t> listAllPids(const IOsPrimitivesMac& osPrimitives)
{
    int32_t maxProc { 0 };
    size_t len { sizeof(maxProc) };
    const auto ret { osPrimitives.sysctlbyname("kern.maxproc", &maxProc, &len, nullptr, 0) };

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading kernel max processes."
        };
    }

    std::vector<pid_t> pids(maxProc);
    const auto processesCount
    {
        osPrimitives.proc_listallpids(pids.data(), static_cast<int32_t>(static_cast<size_t>(maxProc) * sizeof(pid_t)))
    };
    pids.resize(static_cast<size_t>(std::max(processesCount, 0)));
    return pids;
}

#endif // _PROCESSES_WRAPPER_IMPL_MAC_H

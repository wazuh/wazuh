/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "processInfoMac.h"
#include <filesystem>
#include <libproc.h>

std::string resolveProcessName(const pid_t pid, const std::string& fallbackName)
{
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    const auto pathLen { proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) };

    if (pathLen > 0)
    {
        return std::filesystem::path(std::string {pathBuffer}).filename().string();
    }

    return fallbackName;
}

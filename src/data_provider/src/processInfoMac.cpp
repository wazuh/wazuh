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
#include "filesystemHelper.h"
#include <libproc.h>

std::string resolveProcessName(const pid_t pid, const std::string& fallbackName)
{
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    const auto pathLen { proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) };

    if (pathLen > 0)
    {
        return Utils::getFilename(std::string{pathBuffer});
    }

    return fallbackName;
}

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
#ifndef _PROCESS_INFO_MAC_H
#define _PROCESS_INFO_MAC_H

#include <string>
#include <sys/types.h>

/// @brief Resolves a process's name from its full executable path via proc_pidpath(),
/// falling back to the given name when the path lookup fails.
/// @param pid Process ID to look up.
/// @param fallbackName Name to return when proc_pidpath() fails, typically the
/// BSD process info's truncated pbi_name field.
/// @return The untruncated executable basename, or fallbackName on lookup failure.
std::string resolveProcessName(const pid_t pid, const std::string& fallbackName);

#endif //_PROCESS_INFO_MAC_H

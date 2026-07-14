/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * January 30, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HOMEDIR_HPP
#define _HOMEDIR_HPP

#include <filesystem>

namespace Utils
{
    std::filesystem::path findHomeDirectory()
    {
        std::filesystem::path homeDir;
        std::error_code ec;

        // Target-specific env var wins if set (manager/agent separation
        // for co-hosted installs).
#ifdef CLIENT
        const char* envHome = std::getenv("WAZUH_AGENT_HOME");
#else
        const char* envHome = std::getenv("WAZUH_MANAGER_HOME");
#endif
        if (envHome != nullptr && *envHome != '\0')
        {
            homeDir = envHome;
        }
        else
        {
            homeDir = std::filesystem::read_symlink("/proc/self/exe", ec).parent_path();
            if (ec)
            {
                throw std::runtime_error(ec.message());
            }
            if (homeDir.filename() == "bin")
            {
                homeDir.remove_filename();
            }
        }

        // Check if exists and if it is a directory
        if (!std::filesystem::is_directory(homeDir, ec))
        {
            throw std::runtime_error(ec.message());
        }

        return homeDir;
    }
} // namespace Utils

#endif // _HOMEDIR_HPP

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

    homeDir = std::filesystem::read_symlink("/proc/self/exe", ec).parent_path();
    if (homeDir.filename() == "bin")
    {
        homeDir.remove_filename();
    }
    if (ec)
    {
        const char* envHome = std::getenv("WAZUH_HOME");
        if (envHome != nullptr)
        {
            homeDir = envHome;
        }
        else
        {
            throw std::runtime_error(ec.message());
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

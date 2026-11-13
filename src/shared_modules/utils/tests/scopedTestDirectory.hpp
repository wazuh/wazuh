/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * November 13, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SCOPED_TEST_DIRECTORY_HPP
#define SCOPED_TEST_DIRECTORY_HPP

#include <filesystem>
#include <string>
#include <system_error>
#include <unistd.h>

// A directory under the temporary directory, removed when the test ends however it ends
class ScopedTestDirectory final
{
    public:
        explicit ScopedTestDirectory(const std::string& name)
            : m_path {std::filesystem::temp_directory_path() / (name + "_" + std::to_string(::getpid()))}
        {
            std::filesystem::remove_all(m_path);
            std::filesystem::create_directories(m_path);
        }

        ~ScopedTestDirectory()
        {
            std::error_code ignored;
            std::filesystem::remove_all(m_path, ignored);
        }

        ScopedTestDirectory(const ScopedTestDirectory&) = delete;
        ScopedTestDirectory& operator=(const ScopedTestDirectory&) = delete;

        const std::filesystem::path& path() const
        {
            return m_path;
        }

    private:
        std::filesystem::path m_path;
};

#endif // SCOPED_TEST_DIRECTORY_HPP

/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILESYSTEM_HELPER_HPP
#define _FILESYSTEM_HELPER_HPP

#include <filesystem>

/**
 * @brief Helper class to manage filesystem operations
 */
template<typename TDirectoryIterator = std::filesystem::directory_iterator>
class RealFileSystemT
{
public:
    /**
     * @brief Check if a path exists
     * @param path Path to check
     * @return True if the path exists, false otherwise
     */

    static bool exists(const std::filesystem::path& path)
    {
        return std::filesystem::exists(path);
    }

    /**
     * @brief Return the iterator to the first element of a directory
     * @param path Path to check
     * @return The iterator to the first element of a directory
     */
    static TDirectoryIterator directory_iterator(const std::filesystem::path& path)
    {
        return TDirectoryIterator(path);
    }

    /**
     * @brief Is regular file
     * @param path Path to check
     * @return True if the path is a regular file, false otherwise
     */
    static bool is_regular_file(const std::filesystem::path& path)
    {
        return std::filesystem::is_regular_file(path);
    }

    /**
     * @brief Is directory
     * @param path Path to check
     * @return True if the path is a directory, false otherwise
     */
    static bool is_directory(const std::filesystem::path& path)
    {
        return std::filesystem::is_directory(path);
    }
};

using RealFileSystem = RealFileSystemT<>;

#endif // _FILESYSTEM_HELPER_HPP

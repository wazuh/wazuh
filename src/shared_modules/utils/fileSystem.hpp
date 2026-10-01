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

#include <cstdint>
#include <filesystem>

/**
 * @brief Helper class to manage filesystem operations
 */
template <typename TDirectoryIterator = std::filesystem::directory_iterator>
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

        /**
         * @brief Is symbolic link
         * @param path Path to check, the link itself is not followed
         * @return True if the path is a symbolic link, false otherwise
         */
        static bool is_symlink(const std::filesystem::path& path)
        {
            return std::filesystem::is_symlink(path);
        }

        /**
         * @brief Get the size of a file
         * @param path Path to check
         * @return The size of the file in bytes
         */
        static std::uintmax_t file_size(const std::filesystem::path& path)
        {
            return std::filesystem::file_size(path);
        }

        /**
         * @brief Get the full path of a file
         * @param relativePath Relative path to the file
         * @param fileName Name of the file
         * @details This function resolves the full path of a file based on the provided relative path and the file name.
         * @return The full path of the file as a string.
         */
        static std::string resolvePath(const std::string & fileName, const std::string & relativePath)
        {
            return (std::filesystem::path(fileName).parent_path() / relativePath).string();
        }
};

using RealFileSystem = RealFileSystemT<>;

#endif // _FILESYSTEM_HELPER_HPP

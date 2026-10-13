/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BROWSER_EXTENSIONS_SAFE_FILE_READER_HPP
#define _BROWSER_EXTENSIONS_SAFE_FILE_READER_HPP

#include <cstddef>
#include <string>

#ifdef _WIN32
#include <fstream>
#else
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace browser_extensions
{
    // Upper bound for any file read from a user profile. Real manifests and preference files are far smaller.
    constexpr size_t MAX_PROFILE_FILE_SIZE = 16 * 1024 * 1024;

#ifndef _WIN32
    /**
     * @brief Tells whether a file is owned by the given numeric user ID.
     *
     * @param st File status.
     * @param ownerUid Numeric user ID, as a decimal string. An empty or invalid value never matches.
     */
    inline bool isOwnedBy(const struct stat& st, const std::string& ownerUid)
    {
        if (ownerUid.empty() || ownerUid.find_first_not_of("0123456789") != std::string::npos)
        {
            return false;
        }

        errno = 0;
        const unsigned long long uid = std::strtoull(ownerUid.c_str(), nullptr, 10);

        return errno == 0 && static_cast<unsigned long long>(st.st_uid) == uid;
    }
#endif

    /**
     * @brief Reads a regular file from a user profile into a string.
     *
     * The final path component is not followed if it is a symbolic link, the descriptor is validated with
     * fstat() after opening (so no other file type can be read or block the caller), the file must be owned
     * by the owner of the profile and at most MAX_PROFILE_FILE_SIZE bytes are accepted.
     *
     * @param path File to read.
     * @param content Receives the file content on success.
     * @param ownerUid Numeric user ID of the profile owner. Not checked on Windows.
     * @return true if the file is a regular file owned by `ownerUid`, within the size limit, and was fully read.
     */
    inline bool readRegularFile(const std::string& path, std::string& content, const std::string& ownerUid)
    {
        content.clear();

#ifdef _WIN32
        (void)ownerUid;
        std::ifstream file(path, std::ios::binary | std::ios::ate);

        if (!file)
        {
            return false;
        }

        // Check the size before reading, so that a large file is never loaded
        const std::streamoff size = file.tellg();

        if (size < 0 || static_cast<unsigned long long>(size) > MAX_PROFILE_FILE_SIZE)
        {
            return false;
        }

        content.resize(static_cast<size_t>(size));
        file.seekg(0, std::ios::beg);

        if (size > 0 && (!file.read(&content[0], size) || file.gcount() != size))
        {
            content.clear();
            return false;
        }

        return true;
#else
        const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

        if (fd < 0)
        {
            return false;
        }

        struct stat st;

        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || !isOwnedBy(st, ownerUid) ||
                static_cast<size_t>(st.st_size) > MAX_PROFILE_FILE_SIZE)
        {
            ::close(fd);
            return false;
        }

        char buffer[8192];
        bool ok = true;

        while (true)
        {
            // One byte past the limit is enough to detect a file that grew after fstat()
            const size_t room = MAX_PROFILE_FILE_SIZE + 1 - content.size();
            const ssize_t n = ::read(fd, buffer, room < sizeof(buffer) ? room : sizeof(buffer));

            if (n < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }

                ok = false;
                break;
            }

            if (n == 0)
            {
                break;
            }

            content.append(buffer, static_cast<size_t>(n));

            if (content.size() > MAX_PROFILE_FILE_SIZE)
            {
                ok = false;
                break;
            }
        }

        ::close(fd);

        if (!ok)
        {
            content.clear();
        }

        return ok;
#endif
    }

    /**
     * @brief Returns the owner of a user home directory, to use as the profile owner when the user name of
     * the directory is not known to the system.
     *
     * @param path Home directory.
     * @return The numeric user ID as a decimal string, or an empty string if the path is not a directory, is a
     * symbolic link or belongs to root. Always empty on Windows.
     */
    inline std::string homeDirectoryOwner(const std::string& path)
    {
#ifdef _WIN32
        (void)path;
        return "";
#else
        struct stat st;

        if (::lstat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid == 0)
        {
            return "";
        }

        return std::to_string(st.st_uid);
#endif
    }

    /**
     * @brief Tells whether a path is a directory that is not a symbolic link.
     */
    inline bool isPlainDirectory(const std::string& path)
    {
#ifdef _WIN32
        (void)path;
        return true;
#else
        struct stat st;
        return ::lstat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
    }

    /**
     * @brief Tells whether every directory from `base` down to `base`/`relativePath` is a directory that is
     * not a symbolic link. `base` itself is not checked.
     */
    inline bool isPlainDirectoryChain(const std::string& base, const std::string& relativePath)
    {
        std::string current = base;
        size_t start = 0;

        while (start < relativePath.size())
        {
            size_t end = relativePath.find('/', start);

            if (end == std::string::npos)
            {
                end = relativePath.size();
            }

            if (end > start)
            {
                current += "/" + relativePath.substr(start, end - start);

                if (!isPlainDirectory(current))
                {
                    return false;
                }
            }

            start = end + 1;
        }

        return true;
    }
}

#endif // _BROWSER_EXTENSIONS_SAFE_FILE_READER_HPP

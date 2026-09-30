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
#include <iterator>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace browser_extensions
{
    // Upper bound for any file read from a user profile. Real manifests and preference files are far smaller.
    constexpr size_t MAX_PROFILE_FILE_SIZE = 16 * 1024 * 1024;

    /**
     * @brief Reads a regular file from a user profile into a string.
     *
     * The final path component is not followed if it is a symbolic link, the descriptor is validated with
     * fstat() after opening (so no other file type can be read or block the caller) and at most
     * MAX_PROFILE_FILE_SIZE bytes are accepted.
     *
     * @param path File to read.
     * @param content Receives the file content on success.
     * @return true if the file is a regular file within the size limit and was fully read.
     */
    inline bool readRegularFile(const std::string& path, std::string& content)
    {
        content.clear();

#ifdef _WIN32
        std::ifstream file(path, std::ios::binary);

        if (!file)
        {
            return false;
        }

        content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        return !file.bad() && content.size() <= MAX_PROFILE_FILE_SIZE;
#else
        const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

        if (fd < 0)
        {
            return false;
        }

        struct stat st;

        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || static_cast<size_t>(st.st_size) > MAX_PROFILE_FILE_SIZE)
        {
            ::close(fd);
            return false;
        }

        char buffer[8192];
        bool ok = true;

        while (true)
        {
            const ssize_t n = ::read(fd, buffer, sizeof(buffer));

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
}

#endif // _BROWSER_EXTENSIONS_SAFE_FILE_READER_HPP

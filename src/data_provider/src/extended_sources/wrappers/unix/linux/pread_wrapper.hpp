/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <fcntl.h>
#include <unistd.h>

#include "ipread_wrapper.hpp"

/// PreadWrapper class
/// This class is responsible for providing an interface to the file read functions.
class PreadWrapper : public IPreadWrapper
{
    public:
        /// @brief Opens a file for reading.
        /// @return The file descriptor, or -1 on error.
        int open(const char* path) override
        {
            return ::open(path, O_RDONLY | O_CLOEXEC);
        }

        /// @brief Reads count bytes at the given offset without moving the file position.
        /// @return The number of bytes read, 0 at end of file, or -1 on error.
        ssize_t pread(int fd, void* buffer, size_t count, uint64_t offset) override
        {
            // pread64 because the build does not set _FILE_OFFSET_BITS, so pread takes a 32-bit offset on 32-bit targets.
            return ::pread64(fd, buffer, count, static_cast<off64_t>(offset));
        }

        /// @brief Closes a file descriptor.
        void close(int fd) override
        {
            ::close(fd);
        }
};

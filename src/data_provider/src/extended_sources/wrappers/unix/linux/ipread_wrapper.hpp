/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

/// Interface for the file reads done by the last login provider.
/// The offset is 64-bit on every target, so a record far into a sparse file can be requested.
class IPreadWrapper
{
    public:
        /// Destructor
        virtual ~IPreadWrapper() = default;

        /// @brief Opens a file for reading.
        /// @return The file descriptor, or -1 on error.
        virtual int open(const char* path) = 0;

        /// @brief Reads count bytes at the given offset without moving the file position.
        /// @return The number of bytes read, 0 at end of file, or -1 on error.
        virtual ssize_t pread(int fd, void* buffer, size_t count, uint64_t offset) = 0;

        /// @brief Closes a file descriptor.
        virtual void close(int fd) = 0;
};

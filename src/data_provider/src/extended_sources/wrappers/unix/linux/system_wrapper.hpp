/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "isystem_wrapper.hpp"

#include <unistd.h>
#include <cstdio>
#include <cstring>

/// @brief Wrapper class for common system functions.
///
/// Provides an interface to standard system calls for easier mocking and testing.
class SystemWrapper : public ISystemWrapper
{
    public:
        /// @brief Gets configuration information at runtime.
        /// @param name Configuration variable identifier.
        /// @return The value of the configuration variable or -1 on error.
        long sysconf(int name) const override
        {
            return ::sysconf(name);
        }

        /// @brief Opens a file.
        /// @param filename Path to the file.
        /// @param mode Mode string (e.g., "r", "w").
        /// @return Pointer to the opened file stream, or nullptr on failure.
        FILE* fopen(const char* filename, const char* mode) override
        {
            return ::fopen(filename, mode);
        }

        /// @brief Closes a file stream.
        /// @param stream File stream to close.
        /// @return 0 on success, EOF on failure.
        int fclose(FILE* stream) override
        {
            return ::fclose(stream);
        }

        /// @brief Returns a string describing the error code.
        /// @param errnum Error number.
        /// @return Pointer to the error message string.
        char* strerror(int errnum) override
        {
            return ::strerror(errnum);
        }
};

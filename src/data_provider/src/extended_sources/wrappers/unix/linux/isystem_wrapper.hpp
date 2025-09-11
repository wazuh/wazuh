/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once
#include <memory>
#include <string>

// Interface for the system wrapper
class ISystemWrapper
{
    public:
        /// Destructor
        virtual ~ISystemWrapper() = default;

        /// @brief Gets configuration information at runtime.
        /// @param name Configuration variable identifier.
        /// @return The value of the configuration variable or -1 on error.
        virtual long sysconf(int name) const = 0;

        /// @brief Opens a file.
        /// @param filename Path to the file.
        /// @param mode Mode string (e.g., "r", "w").
        /// @return Pointer to the opened file stream, or nullptr on failure.
        virtual FILE* fopen(const char* filename, const char* mode) = 0;

        /// @brief Closes a file stream.
        /// @param stream File stream to close.
        /// @return 0 on success, EOF on failure.
        virtual int fclose(FILE* stream) = 0;

        /// @brief Returns a string describing the error code.
        /// @param errnum Error number.
        /// @return Pointer to the error message string.
        virtual char* strerror(int errnum) = 0;
};

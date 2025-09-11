/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "iutmpx_wrapper.hpp"
#include <utmpx.h>

/// @brief Wrapper class for utmpx-related system calls.
///
/// Provides access to user session records using the utmpx API.
class UtmpxWrapper : public IUtmpxWrapper
{
    public:
        /// @brief Sets the utmpx file to be used by the library functions.
        /// @param file Path to the utmpx file.
        void utmpxname(const char* file) override
        {
            ::utmpxname(file);
        }

        /// @brief Resets the input stream to the beginning of the utmpx file.
        void setutxent() override
        {
            ::setutxent();
        }

        /// @brief Closes the utmpx file.
        void endutxent() override
        {
            ::endutxent();
        }

        /// @brief Reads the next entry from the utmpx file.
        /// @return A pointer to the next utmpx structure, or nullptr if none.
        struct utmpx* getutxent() override
        {
            return ::getutxent();
        }
};

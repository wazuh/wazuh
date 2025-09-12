/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <utmpx.h>

// Interface for the utmpx wrapper
class IUtmpxWrapper
{
    public:
        /// Destructor
        virtual ~IUtmpxWrapper() = default;

        /// @brief Sets the utmpx file to be used by the library functions.
        /// @param file Path to the utmpx file.
        virtual void utmpxname(const char* file) = 0;

        /// @brief Resets the input stream to the beginning of the utmpx file.
        virtual void setutxent() = 0;

        /// @brief Closes the utmpx file.
        virtual void endutxent() = 0;

        /// @brief Reads the next entry from the utmpx file.
        /// @return A pointer to the next utmpx structure, or nullptr if none.
        virtual struct utmpx* getutxent() = 0;
};

/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <pwd.h>

// Interface for the pwd darwin wrapper
class IPasswdWrapperDarwin
{
    public:
        /// Destructor
        virtual ~IPasswdWrapperDarwin() = default;

        /// @brief Retrieves the passwd entry for the given username.
        /// @param name The username to search for.
        /// @return A pointer to the passwd structure, or nullptr if not found.
        virtual struct passwd* getpwnam(const char* name) = 0;

        /// @brief Retrieves the passwd entry for the given user ID.
        /// @param uid The user ID to search for.
        /// @return A pointer to the passwd structure, or nullptr if not found.
        virtual struct passwd* getpwuid(uid_t uid) = 0;

        /// @brief Rewinds the passwd database to the beginning.
        virtual void setpwent() = 0;

        /// @brief Retrieves the next entry from the passwd database.
        /// @return A pointer to the passwd structure, or nullptr if no more entries.
        virtual struct passwd* getpwent() = 0;

        /// @brief Closes the passwd database.
        virtual void endpwent() = 0;
};

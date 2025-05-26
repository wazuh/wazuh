/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ipasswd_wrapper_darwin.hpp"

/// @brief Wrapper class for macOS-specific passwd database access.
///
/// Encapsulates system calls used to retrieve user information on Darwin/macOS,
/// allowing for dependency injection and easier testing.
class PasswdWrapperDarwin : public IPasswdWrapperDarwin
{
    public:
        /// @brief Retrieves the passwd entry for the given username.
        /// @param name The username to search for.
        /// @return A pointer to the passwd structure, or nullptr if not found.
        struct passwd* getpwnam(const char* name) override
        {
            return ::getpwnam(name);
        }

        /// @brief Retrieves the passwd entry for the given user ID.
        /// @param uid The user ID to search for.
        /// @return A pointer to the passwd structure, or nullptr if not found.
        struct passwd* getpwuid(uid_t uid) override
        {
            return ::getpwuid(uid);
        }

        /// @brief Rewinds the passwd database to the beginning.
        void setpwent() override
        {
            ::setpwent();
        }

        /// @brief Retrieves the next entry from the passwd database.
        /// @return A pointer to the passwd structure, or nullptr if no more entries.
        struct passwd* getpwent() override
        {
            return ::getpwent();
        }

        /// @brief Closes the passwd database.
        void endpwent() override
        {
            ::endpwent();
        }
};

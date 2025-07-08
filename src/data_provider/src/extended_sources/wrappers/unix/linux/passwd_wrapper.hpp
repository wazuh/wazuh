/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ipasswd_wrapper.hpp"

/// @brief Wrapper class for functions related to the passwd database.
///
/// Encapsulates standard library functions for accessing user account information,
/// allowing easier mocking and testing.
class PasswdWrapperLinux : public IPasswdWrapperLinux
{
    public:
        /// @brief Reads a passwd entry from a file stream.
        /// @param stream The file stream to read from (typically /etc/passwd).
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int fgetpwent_r(FILE* stream, struct passwd* pwd,
                        char* buf, size_t buflen, struct passwd** result) override
        {
            return ::fgetpwent_r(stream, pwd, buf, buflen, result);
        }

        /// @brief Rewinds the passwd database to the beginning.
        void setpwent() override
        {
            ::setpwent();
        }

        /// @brief Retrieves the next entry from the passwd database.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int getpwent_r(struct passwd* pwd, char* buf,
                       size_t buflen, struct passwd** result) override
        {
            return ::getpwent_r(pwd, buf, buflen, result);
        }

        /// @brief Closes the passwd database.
        void endpwent() override
        {
            ::endpwent();
        }

        /// @brief Retrieves the next entry from the passwd database.
        /// @return A pointer to the next passwd structure, or nullptr if there are no more entries.
        struct passwd* getpwent() override
        {
            return ::getpwent();
        }

        /// @brief Retrieves the passwd entry for the given user ID.
        /// @param uid User ID to search.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int getpwuid_r(uid_t uid, struct passwd* pwd,
                       char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwuid_r(uid, pwd, buf, buflen, result);
        }

        /// @brief Retrieves the passwd entry for the given username.
        /// @param name Username to search.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int getpwnam_r(const char* name, struct passwd* pwd,
                       char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwnam_r(name, pwd, buf, buflen, result);
        }
};

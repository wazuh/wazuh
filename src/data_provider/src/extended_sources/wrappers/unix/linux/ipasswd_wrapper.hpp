/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once
#include <sys/types.h>
#include <pwd.h>

// Interface for the pwd linux wrapper
class IPasswdWrapperLinux
{
    public:
        /// Destructor
        virtual ~IPasswdWrapperLinux() = default;

        /// @brief Reads a passwd entry from a file stream.
        /// @param stream The file stream to read from (typically /etc/passwd).
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        virtual int fgetpwent_r(FILE* stream, struct passwd* pwd,
                                char* buf, size_t buflen, struct passwd** result) = 0;

        /// @brief Rewinds the passwd database to the beginning.
        virtual void setpwent() = 0;

        /// @brief Retrieves the next entry from the passwd database.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        virtual int getpwent_r(struct passwd* pwd, char* buf,
                               size_t buflen, struct passwd** result) = 0;

        /// @brief Closes the passwd database.
        virtual void endpwent() = 0;

        /// @brief Retrieves the passwd entry for the given user ID.
        /// @param uid User ID to search.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        virtual int getpwuid_r(uid_t uid, struct passwd* pwd,
                               char* buf, size_t buflen, struct passwd** result) = 0;

        /// @brief Retrieves the passwd entry for the given username.
        /// @param name Username to search.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        virtual int getpwnam_r(const char* name, struct passwd* pwd,
                               char* buf, size_t buflen, struct passwd** result) = 0;
};

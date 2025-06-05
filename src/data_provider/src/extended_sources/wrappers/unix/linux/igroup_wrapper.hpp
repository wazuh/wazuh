/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <grp.h>

/// @brief Interface for group-related operations on Linux systems.
///
/// Provides methods to retrieve group lists for users, allowing for dependency injection
/// and easier testing. This interface abstracts the system calls used to interact with the group database.
class IGroupWrapperLinux
{
    public:
        /// @brief Default constructor.
        virtual ~IGroupWrapperLinux() = default;

        /// @brief Retrieves the group entry for a given group ID.
        /// @param gid The group ID to search for.
        /// @param resultbuf A pointer to a group structure where the result will be stored.
        /// @param buffer A buffer to hold the string data for the group entry.
        /// @param buflen The size of the buffer.
        /// @param result A pointer to a group structure pointer that will point to the result.
        /// @return 0 on success, or an error code on failure.
        virtual int getgrgid_r(gid_t gid, struct group* resultbuf, char* buffer, size_t buflen, struct group** result) const = 0;

        /// @brief Retrieves the group entry for a given group name.
        /// @param resultbuf A pointer to a group structure where the result will be stored.
        /// @param buffer A buffer to hold the string data for the group entry.
        /// @param buflen The size of the buffer.
        /// @param result A pointer to a group structure pointer that will point to the result.
        virtual int getgrent_r(struct group* resultbuf, char* buffer, size_t buflen, struct group** result) const = 0;

        /// @brief Rewind the group-file stream.
        virtual void setgrent() const = 0;

        /// @brief Close the group-file stream.
        virtual void endgrent() const = 0;

        /// @brief Retrieves the list of groups for a user.
        /// @param user The username for which to retrieve the group list.
        /// @param group The primary group ID of the user.
        /// @param groups Pointer to an array where the group IDs will be stored.
        /// @param ngroups Pointer to an integer that indicates the size of the groups array.
        /// @return The number of groups the user belongs to, or -1 on error.
        virtual int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const = 0;
};

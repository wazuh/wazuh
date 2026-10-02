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
#include <string>
#include <unordered_map>

/// Failed authentications of an account. When known is false, the host offers no usable source.
struct AuthFailures
{
    bool known;
    uint64_t count;
    uint64_t latest;
};

/// AuthFailuresProvider class
/// This class is responsible for counting the failed authentications of an account.
///
/// The count is the failed attempts recorded in btmp since the account last logged in, which matches
/// what macOS reports from its account policy: a figure that a successful login clears. pam_faillock
/// is deliberately not read. Its tally is a lockout counter rather than a record of attempts: it is
/// cleared only by a successful password authentication, so a login by public key leaves it standing,
/// it lives on tmpfs and is lost on reboot, and its directory exists on RHEL whether or not the module
/// is in use. None of those answer "how many failed authentications has this account had".
class AuthFailuresProvider
{
    public:
        /// Constructor
        /// @param btmpPath Path of the btmp file.
        /// @param btmpTailBytes Maximum number of bytes read from the end of btmp.
        AuthFailuresProvider(const std::string& btmpPath, size_t btmpTailBytes);

        /// Default constructor
        /// This constructor uses /var/log/btmp.
        AuthFailuresProvider();

        /// Reads btmp. It has to be called once before get().
        /// @param lastLoginByName Epoch seconds of the last login of every collected account, 0 when the
        ///        account has never logged in.
        /// @param lastLoginKnown Whether the host offers any source of last logins. Without one the
        ///        count cannot be anchored to anything and is reported as unknown.
        void load(const std::unordered_map<std::string, uint32_t>& lastLoginByName, bool lastLoginKnown);

        /// Returns the failed authentications of an account.
        /// @param userName The name of the account.
        AuthFailures get(const std::string& userName) const;

    private:
        /// Reads btmp and its rotated generation, counting per account the failures newer than its
        /// last login.
        /// @return false when neither file can be read or both hold no record.
        bool loadBtmp(const std::unordered_map<std::string, uint32_t>& lastLoginByName);

        /// Counts the failures of one btmp file, newest records first, spending from a shared budget.
        /// @param path Path of the file.
        /// @param lastLoginByName Epoch seconds of the last login of every collected account.
        /// @param budgetBytes Bytes still available to read, reduced by what this file consumed.
        /// @return false when the file is missing, empty, or could not be read to the end.
        bool readBtmpFile(const std::string& path,
                          const std::unordered_map<std::string, uint32_t>& lastLoginByName,
                          size_t& budgetBytes);

        std::string m_btmpPath;
        size_t m_btmpTailBytes;

        bool m_btmpKnown;
        std::unordered_map<std::string, AuthFailures> m_btmpFailures;
};

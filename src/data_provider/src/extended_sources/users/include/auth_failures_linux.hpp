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

/// Failed authentications of an account. When known is false, no source exists on the host.
struct AuthFailures
{
    bool known;
    uint64_t count;
    uint64_t latest;
};

/// AuthFailuresProvider class
/// This class is responsible for counting the failed authentications of an account.
/// It reads pam_faillock when the host enforces it, and otherwise the failures in btmp since the last login.
class AuthFailuresProvider
{
    public:
        /// Constructor
        /// @param faillockConf Path of the faillock configuration.
        /// @param pamDir Directory of the PAM stacks.
        /// @param btmpPath Path of the btmp file.
        /// @param btmpTailBytes Maximum number of bytes read from the end of btmp.
        AuthFailuresProvider(const std::string& faillockConf, const std::string& pamDir, const std::string& btmpPath, size_t btmpTailBytes);

        /// Default constructor
        /// This constructor uses /etc/security/faillock.conf, /etc/pam.d and /var/log/btmp.
        AuthFailuresProvider();

        /// Selects the source and, for btmp, reads it. It has to be called once before get().
        /// @param lastLoginByName Epoch seconds of the last login of every collected account, 0 when unknown.
        void load(const std::unordered_map<std::string, uint32_t>& lastLoginByName);

        /// Returns the failed authentications of an account.
        /// @param userName The name of the account.
        AuthFailures get(const std::string& userName) const;

    private:
        /// Tells whether an uncommented auth line of the PAM stacks calls pam_faillock.
        bool isFaillockActive() const;

        /// Reads the failures of an account from its faillock tally file.
        AuthFailures readFaillock(const std::string& userName) const;

        /// Reads btmp and counts, per collected account, the failures newer than its last login.
        /// @return false when btmp cannot be read.
        bool loadBtmp(const std::unordered_map<std::string, uint32_t>& lastLoginByName);

        std::string m_faillockConf;
        std::string m_pamDir;
        std::string m_btmpPath;
        size_t m_btmpTailBytes;

        /// The faillock tally directory, empty when faillock is not the source.
        std::string m_faillockDir;

        bool m_btmpKnown;
        std::unordered_map<std::string, AuthFailures> m_btmpFailures;
};

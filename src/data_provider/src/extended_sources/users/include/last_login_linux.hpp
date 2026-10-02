/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <sys/types.h>

#include "ipread_wrapper.hpp"

/// Converts a lastlog timestamp to the type the inventory reports.
///
/// glibc sizes the on-disk field per platform. Where it is 32 bits a time past 2038-01-19 is stored
/// negative and has to be read back unsigned to recover it. Where it is 64 bits it does not wrap, so
/// a negative value is not a login at all, and a value past the reported range is held at the maximum
/// rather than wrapping round. Templated so both branches can be exercised on either architecture.
/// @param raw The timestamp as held in the record.
template<typename T>
uint32_t lastLoginFromRecordTime(T raw)
{
    if constexpr (sizeof(T) <= sizeof(int32_t))
    {
        return static_cast<uint32_t>(raw);
    }
    else
    {
        if (raw <= 0)
        {
            return 0;
        }

        return static_cast<uint32_t>(std::min<int64_t>(static_cast<int64_t>(raw), UINT32_MAX));
    }
}

/// LastLoginProvider class
/// This class is responsible for finding the most recent login of an account, whether or not it has a session open.
/// It reads lastlog by seeking to the record of the uid, and lastlog2 when its database exists.
class LastLoginProvider
{
    public:
        /// Constructor
        /// @param lastlogPath Path of the lastlog file.
        /// @param lastlog2Path Path of the lastlog2 database.
        /// @param reader A shared pointer to an IPreadWrapper object.
        LastLoginProvider(const std::string& lastlogPath, const std::string& lastlog2Path, std::shared_ptr<IPreadWrapper> reader);

        /// Default constructor
        /// This constructor uses /var/log/lastlog and /var/lib/lastlog/lastlog2.db.
        LastLoginProvider();

        ~LastLoginProvider();

        LastLoginProvider(const LastLoginProvider&) = delete;
        LastLoginProvider& operator=(const LastLoginProvider&) = delete;

        /// Looks up the most recent login of an account.
        /// @param uid The uid of the account.
        /// @param userName The name of the account.
        /// @return Epoch seconds of the most recent recorded login, 0 when no source has one.
        uint32_t lastLogin(uid_t uid, const std::string& userName) const;

        /// Tells whether the host offers any source of last logins.
        /// Without one every account looks as if it had never logged in, which makes "failures since
        /// the last login" unanswerable rather than zero.
        bool hasSource() const;

    private:
        /// Reads every account of the lastlog2 database into m_lastlog2.
        void loadLastlog2(const std::string& lastlog2Path);

        /// A shared pointer to an IPreadWrapper object.
        std::shared_ptr<IPreadWrapper> m_reader;

        /// The lastlog file descriptor, -1 when the file cannot be opened.
        int m_lastlogFd;

        /// Last login by account name, from lastlog2.
        std::unordered_map<std::string, uint32_t> m_lastlog2;
};

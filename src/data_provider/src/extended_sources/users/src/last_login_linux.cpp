/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "last_login_linux.hpp"
#include "pread_wrapper.hpp"

#include <lastlog.h>

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <system_error>

constexpr const char* DEFAULT_LASTLOG_PATH = "/var/log/lastlog";
constexpr const char* DEFAULT_LASTLOG2_PATH = "/var/lib/lastlog/lastlog2.db";
constexpr int LASTLOG2_BUSY_TIMEOUT_MS = 100;

// On-disk record of lastlog, taken from the system so the layout matches what shadow and pam write.
// glibc selects ll_time's width from __WORDSIZE_TIME64_COMPAT32, so the record is 292 bytes where
// that macro is 1 (x86_64) and 296 where it is 0 (aarch64 among others). Hardcoding either width
// shifts every offset by 4 bytes per uid on the other, which reads a different account's record.
using LastlogRecord = struct lastlog;

static_assert(sizeof(LastlogRecord) == sizeof(int32_t) + 32 + 256 ||
              sizeof(LastlogRecord) == sizeof(int64_t) + 32 + 256,
              "unexpected lastlog record layout");

LastLoginProvider::LastLoginProvider(const std::string& lastlogPath, const std::string& lastlog2Path, std::shared_ptr<IPreadWrapper> reader)
    : m_reader(std::move(reader))
    , m_lastlogFd(m_reader->open(lastlogPath.c_str()))
    , m_lastlogHasRecords(false)
{
    // An empty lastlog opens like any other, so opening it says nothing about whether the host keeps
    // last logins there. Reading the first record tells them apart: a file holding no record returns
    // nothing, while one extended to any uid returns bytes, zeroed or not, from the hole or the record.
    if (m_lastlogFd >= 0)
    {
        LastlogRecord probe {};
        m_lastlogHasRecords = m_reader->pread(m_lastlogFd, &probe, sizeof(probe), 0) > 0;
    }

    loadLastlog2(lastlog2Path);
}

LastLoginProvider::LastLoginProvider()
    : LastLoginProvider(DEFAULT_LASTLOG_PATH, DEFAULT_LASTLOG2_PATH, std::make_shared<PreadWrapper>())
{
}

LastLoginProvider::~LastLoginProvider()
{
    if (m_lastlogFd >= 0)
    {
        m_reader->close(m_lastlogFd);
    }
}

void LastLoginProvider::loadLastlog2(const std::string& lastlog2Path)
{
    std::error_code ec;

    if (!std::filesystem::is_regular_file(lastlog2Path, ec))
    {
        return;
    }

    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;

    // Read only and short-lived, so pam_lastlog2 never waits for the agent when a user logs in.
    if (sqlite3_open_v2(lastlog2Path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK)
    {
        sqlite3_busy_timeout(db, LASTLOG2_BUSY_TIMEOUT_MS);

        if (sqlite3_prepare_v2(db, "SELECT Name, Time FROM Lastlog2", -1, &stmt, nullptr) == SQLITE_OK)
        {
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const auto* name = sqlite3_column_text(stmt, 0);
                const auto loginTime = sqlite3_column_int64(stmt, 1);

                if (name != nullptr && loginTime > 0 && loginTime <= UINT32_MAX)
                {
                    m_lastlog2[reinterpret_cast<const char*>(name)] = static_cast<uint32_t>(loginTime);
                }
            }
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

bool LastLoginProvider::hasSource() const
{
    return m_lastlogHasRecords || !m_lastlog2.empty();
}

uint32_t LastLoginProvider::lastLogin(uid_t uid, const std::string& userName) const
{
    uint32_t lastLogin = 0;

    if (m_lastlogFd >= 0)
    {
        LastlogRecord record {};
        // lastlog is sparse and indexed by uid, so seek to the record instead of reading the file.
        const auto offset = static_cast<uint64_t>(uid) * sizeof(LastlogRecord);

        if (m_reader->pread(m_lastlogFd, &record, sizeof(record), offset) == static_cast<ssize_t>(sizeof(record)))
        {
            lastLogin = lastLoginFromRecordTime(record.ll_time);
        }
    }

    const auto lastlog2 = m_lastlog2.find(userName);

    if (lastlog2 != m_lastlog2.end())
    {
        lastLogin = std::max(lastLogin, lastlog2->second);
    }

    return lastLogin;
}

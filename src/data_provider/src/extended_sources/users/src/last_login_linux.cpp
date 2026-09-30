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
#include "filesystemHelper.h"

#include <sqlite3.h>

#include <algorithm>

constexpr const char* DEFAULT_LASTLOG_PATH = "/var/log/lastlog";
constexpr const char* DEFAULT_LASTLOG2_PATH = "/var/lib/lastlog/lastlog2.db";
constexpr int LASTLOG2_BUSY_TIMEOUT_MS = 100;

// On-disk record of lastlog. <lastlog.h> is not used because glibc changes ll_time to 64 bits on some builds.
struct LastlogRecord
{
    int32_t ll_time;
    char ll_line[32];
    char ll_host[256];
};

static_assert(sizeof(LastlogRecord) == 292, "lastlog records are 292 bytes");

LastLoginProvider::LastLoginProvider(const std::string& lastlogPath, const std::string& lastlog2Path, std::shared_ptr<IPreadWrapper> reader)
    : m_reader(std::move(reader))
    , m_lastlogFd(m_reader->open(lastlogPath.c_str()))
{
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
    if (!Utils::existsRegular(lastlog2Path))
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
            // Unsigned, so a login after 2038-01-19 is not read as negative.
            lastLogin = static_cast<uint32_t>(record.ll_time);
        }
    }

    const auto lastlog2 = m_lastlog2.find(userName);

    if (lastlog2 != m_lastlog2.end())
    {
        lastLogin = std::max(lastLogin, lastlog2->second);
    }

    return lastLogin;
}

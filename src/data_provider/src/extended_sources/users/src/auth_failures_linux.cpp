/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "auth_failures_linux.hpp"
#include "filesystemHelper.h"

#include <utmpx.h>

#include <algorithm>
#include <cstring>
#include <fstream>

constexpr const char* DEFAULT_BTMP_PATH = "/var/log/btmp";
// About 175000 failed attempts.
constexpr size_t DEFAULT_BTMP_TAIL_BYTES = 64 * 1024 * 1024;

AuthFailuresProvider::AuthFailuresProvider(const std::string& btmpPath, size_t btmpTailBytes)
    : m_btmpPath(btmpPath)
    , m_btmpTailBytes(btmpTailBytes)
    , m_btmpKnown(false)
{
}

AuthFailuresProvider::AuthFailuresProvider()
    : AuthFailuresProvider(DEFAULT_BTMP_PATH, DEFAULT_BTMP_TAIL_BYTES)
{
}

bool AuthFailuresProvider::loadBtmp(const std::unordered_map<std::string, uint32_t>& lastLoginByName)
{
    if (!Utils::existsRegular(m_btmpPath))
    {
        return false;
    }

    std::ifstream btmp(m_btmpPath, std::ios::binary | std::ios::ate);

    if (!btmp.is_open())
    {
        return false;
    }

    const auto recordSize = sizeof(struct utmpx);
    const auto fileSize = static_cast<uint64_t>(btmp.tellg());
    const auto totalRecords = fileSize / recordSize;

    // A btmp holding no record is not evidence that nobody failed to authenticate, only that nothing
    // has been written to it. Every distro ships the file empty, and a system whose sshd does not
    // record failures there keeps it that way, so answering zero here is the false zero this collector
    // exists to avoid. Report the count as unknown until the file carries at least one record.
    if (totalRecords == 0)
    {
        return false;
    }

    // Records are appended in time order, so the tail holds the newest ones. A partial record at the end is ignored.
    const auto readRecords = std::min<uint64_t>(totalRecords, m_btmpTailBytes / recordSize);

    btmp.seekg(static_cast<std::streamoff>((totalRecords - readRecords) * recordSize));

    struct utmpx entry {};

    while (btmp.read(reinterpret_cast<char*>(&entry), recordSize))
    {
        const auto user = std::string(entry.ut_user, strnlen(entry.ut_user, sizeof(entry.ut_user)));
        const auto lastLogin = lastLoginByName.find(user);
        const auto failureTime = static_cast<uint32_t>(entry.ut_tv.tv_sec);

        // Attempts on names that are not collected accounts cannot be attributed.
        if (lastLogin != lastLoginByName.end() && failureTime > lastLogin->second)
        {
            auto& failures = m_btmpFailures[user];
            failures.known = true;
            ++failures.count;
            failures.latest = std::max<uint64_t>(failures.latest, failureTime);
        }
    }

    // Reaching the end of the file is not an error, a read failure before it is. A torn record at the
    // end is normal for an append-only log and is ignored, but a read that stopped for any other
    // reason leaves eofbit clear and is reported as unknown rather than as a complete count.
    return btmp.eof();
}

void AuthFailuresProvider::load(const std::unordered_map<std::string, uint32_t>& lastLoginByName, bool lastLoginKnown)
{
    m_btmpFailures.clear();
    m_btmpKnown = false;

    // The count is "failures since the account last logged in". Where the host records no last login
    // at all, every account looks as if it had never logged in, and every failure btmp still holds
    // would be counted against it, however long ago and however many times that account has since
    // logged in successfully. That is a wrong number rather than a missing one, so report nothing.
    if (!lastLoginKnown)
    {
        return;
    }

    m_btmpKnown = loadBtmp(lastLoginByName);
}

AuthFailures AuthFailuresProvider::get(const std::string& userName) const
{
    if (!m_btmpKnown)
    {
        return {false, 0, 0};
    }

    const auto failures = m_btmpFailures.find(userName);
    return failures != m_btmpFailures.end() ? failures->second : AuthFailures {true, 0, 0};
}

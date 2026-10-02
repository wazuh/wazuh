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

bool AuthFailuresProvider::readBtmpFile(const std::string& path,
                                        const std::unordered_map<std::string, uint32_t>& lastLoginByName,
                                        size_t& budgetBytes)
{
    if (budgetBytes == 0 || !Utils::existsRegular(path))
    {
        return false;
    }

    std::ifstream btmp(path, std::ios::binary | std::ios::ate);

    if (!btmp.is_open())
    {
        return false;
    }

    const auto recordSize = sizeof(struct utmpx);
    const auto fileSize = static_cast<uint64_t>(btmp.tellg());
    const auto totalRecords = fileSize / recordSize;

    if (totalRecords == 0)
    {
        return false;
    }

    // Records are appended in time order, so the tail holds the newest ones. A partial record at the end is ignored.
    const auto readRecords = std::min<uint64_t>(totalRecords, budgetBytes / recordSize);

    if (readRecords == 0)
    {
        return false;
    }

    btmp.seekg(static_cast<std::streamoff>((totalRecords - readRecords) * recordSize));

    struct utmpx entry {};
    uint64_t consumed = 0;

    while (consumed < readRecords && btmp.read(reinterpret_cast<char*>(&entry), recordSize))
    {
        ++consumed;
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

    budgetBytes -= std::min<size_t>(budgetBytes, static_cast<size_t>(consumed * recordSize));

    // Reaching the end of the file is not an error, a read failure before it is. A torn record at the
    // end is normal for an append-only log and is ignored, but a read that stopped for any other
    // reason leaves eofbit clear, and the count from this file is then not trustworthy.
    return consumed == readRecords || btmp.eof();
}

bool AuthFailuresProvider::loadBtmp(const std::unordered_map<std::string, uint32_t>& lastLoginByName)
{
    auto budget = m_btmpTailBytes;
    auto known = false;

    // The rotated file is read as well as the live one. logrotate replaces btmp with an empty file
    // every month and keeps one generation beside it, so reading only the live file loses up to a
    // month of failures and, worse, makes every account on the host flip to unknown and back as soon
    // as the next failure is recorded. With the rotated generation included the count survives a
    // rotation, which is what "since the account last logged in" is supposed to mean.
    //
    // Newest first, so the byte budget is spent on the most recent failures when both files are large.
    // A rotated file that the distribution compresses is not read, and if the live file is empty the
    // count is then correctly reported as unknown rather than as zero.
    const std::string paths[] {m_btmpPath, m_btmpPath + ".1"};

    for (const auto& path : paths)
    {
        known = readBtmpFile(path, lastLoginByName, budget) || known;
    }

    return known;
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

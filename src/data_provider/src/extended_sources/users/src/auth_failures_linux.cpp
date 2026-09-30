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
#include "stringHelper.h"

#include <utmpx.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <vector>

constexpr const char* DEFAULT_FAILLOCK_CONF = "/etc/security/faillock.conf";
constexpr const char* DEFAULT_PAM_DIR = "/etc/pam.d";
constexpr const char* DEFAULT_BTMP_PATH = "/var/log/btmp";
constexpr const char* DEFAULT_FAILLOCK_DIR = "/var/run/faillock";
// About 175000 failed attempts.
constexpr size_t DEFAULT_BTMP_TAIL_BYTES = 64 * 1024 * 1024;
constexpr uint16_t TALLY_STATUS_VALID = 0x1;

// On-disk record of a pam_faillock tally file.
struct TallyRecord
{
    char source[52];
    uint16_t reserved;
    uint16_t status;
    uint64_t time;
};

static_assert(sizeof(TallyRecord) == 64, "faillock records are 64 bytes");

AuthFailuresProvider::AuthFailuresProvider(const std::string& faillockConf, const std::string& pamDir, const std::string& btmpPath, size_t btmpTailBytes)
    : m_faillockConf(faillockConf)
    , m_pamDir(pamDir)
    , m_btmpPath(btmpPath)
    , m_btmpTailBytes(btmpTailBytes)
    , m_btmpKnown(false)
{
}

AuthFailuresProvider::AuthFailuresProvider()
    : AuthFailuresProvider(DEFAULT_FAILLOCK_CONF, DEFAULT_PAM_DIR, DEFAULT_BTMP_PATH, DEFAULT_BTMP_TAIL_BYTES)
{
}

bool AuthFailuresProvider::isFaillockActive() const
{
    for (const auto& fileName : Utils::enumerateDir(m_pamDir))
    {
        // The file is opened through its path, so a symlink such as authselect's system-auth is followed.
        const auto path = Utils::joinPaths(m_pamDir, fileName);

        if (!Utils::existsRegular(path))
        {
            continue;
        }

        for (auto& line : Utils::split(Utils::getFileContent(path), '\n'))
        {
            Utils::trimSpaces(line);

            if (line.rfind("auth", 0) == 0 && line.find("pam_faillock.so") != std::string::npos)
            {
                return true;
            }
        }
    }

    return false;
}

AuthFailures AuthFailuresProvider::readFaillock(const std::string& userName) const
{
    AuthFailures failures {true, 0, 0};

    if (userName.find('/') != std::string::npos)
    {
        return failures;
    }

    // pam_faillock creates the file on the first failure and truncates it on a success, so no file means no failures.
    std::ifstream tally(m_faillockDir + "/" + userName, std::ios::binary);
    TallyRecord record {};

    while (tally.read(reinterpret_cast<char*>(&record), sizeof(record)))
    {
        if (record.status & TALLY_STATUS_VALID)
        {
            ++failures.count;
            failures.latest = std::max(failures.latest, record.time);
        }
    }

    return failures;
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

    // Reaching the end of the file is not an error, a read failure before it is.
    return btmp.eof();
}

void AuthFailuresProvider::load(const std::unordered_map<std::string, uint32_t>& lastLoginByName)
{
    m_faillockDir.clear();
    m_btmpKnown = false;
    m_btmpFailures.clear();

    if (isFaillockActive())
    {
        std::string dir = DEFAULT_FAILLOCK_DIR;

        for (auto& line : Utils::split(Utils::getFileContent(m_faillockConf), '\n'))
        {
            Utils::trimSpaces(line);
            const auto separator = line.find('=');

            if (line.empty() || line[0] == '#' || separator == std::string::npos)
            {
                continue;
            }

            auto key = line.substr(0, separator);
            auto value = line.substr(separator + 1);
            Utils::trimSpaces(key);
            Utils::trimSpaces(value);

            if (key == "dir" && !value.empty())
            {
                dir = value;
            }
        }

        if (Utils::existsDir(dir))
        {
            m_faillockDir = dir;
            return;
        }
    }

    m_btmpKnown = loadBtmp(lastLoginByName);
}

AuthFailures AuthFailuresProvider::get(const std::string& userName) const
{
    if (!m_faillockDir.empty())
    {
        return readFaillock(userName);
    }

    if (!m_btmpKnown)
    {
        return {false, 0, 0};
    }

    const auto failures = m_btmpFailures.find(userName);
    return failures != m_btmpFailures.end() ? failures->second : AuthFailures {true, 0, 0};
}

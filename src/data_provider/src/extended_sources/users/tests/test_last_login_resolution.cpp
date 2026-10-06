/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"

#include "last_login_resolution.hpp"

#include <map>
#include <string>

namespace
{
    /// A stand-in for LastLoginProvider: answers from a table instead of reading the host.
    class FakeLastLoginProvider
    {
        public:
            explicit FakeLastLoginProvider(std::map<std::string, uint32_t> recorded)
                : m_recorded(std::move(recorded)) {}

            uint32_t lastLogin(uid_t, const std::string& userName) const
            {
                const auto entry = m_recorded.find(userName);
                return entry != m_recorded.end() ? entry->second : 0;
            }

        private:
            std::map<std::string, uint32_t> m_recorded;
    };

    nlohmann::json users(const std::vector<std::string>& names)
    {
        auto array = nlohmann::json::array();
        int uid = 1000;

        for (const auto& name : names)
        {
            array.push_back({{"username", name}, {"uid", uid++}});
        }

        return array;
    }

    nlohmann::json session(const std::string& user, int32_t time, const std::string& type = "user")
    {
        return {{"user", user}, {"time", time}, {"type", type}};
    }
}

TEST(LastLoginResolutionTests, RecordedLoginsAreReturnedPerAccount)
{
    FakeLastLoginProvider provider({{"alice", 500}, {"bob", 0}});

    const auto resolved = resolveLastLogins(users({"alice", "bob"}), nlohmann::json::array(), provider);

    EXPECT_TRUE(resolved.known);
    EXPECT_EQ(resolved.byName.at("alice"), 500u);
    EXPECT_EQ(resolved.byName.at("bob"), 0u);
}

TEST(LastLoginResolutionTests, NoRecordedLoginAnywhereIsNotKnown)
{
    // Debian 13 ships no lastlog, and a file that reads back as zeros is no better than none.
    FakeLastLoginProvider provider({{"alice", 0}, {"bob", 0}});

    const auto resolved = resolveLastLogins(users({"alice", "bob"}), nlohmann::json::array(), provider);

    EXPECT_FALSE(resolved.known);
}

TEST(LastLoginResolutionTests, AnOpenSessionDoesNotMakeTheCountKnowable)
{
    // The regression this function exists to prevent: with no recorded login anywhere, one account
    // connected at scan time must not re-enable counting for the others, which would anchor them at
    // the epoch and count every failure the log still holds against them.
    FakeLastLoginProvider provider({{"alice", 0}, {"bob", 0}});
    nlohmann::json live = nlohmann::json::array({session("alice", 900)});

    const auto resolved = resolveLastLogins(users({"alice", "bob"}), live, provider);

    EXPECT_FALSE(resolved.known);
    // The session still dates alice's own last login.
    EXPECT_EQ(resolved.byName.at("alice"), 900u);
    EXPECT_EQ(resolved.byName.at("bob"), 0u);
}

TEST(LastLoginResolutionTests, AnOpenSessionRefinesAnAccountAlreadyRecorded)
{
    FakeLastLoginProvider provider({{"alice", 500}});
    nlohmann::json live = nlohmann::json::array({session("alice", 900)});

    const auto resolved = resolveLastLogins(users({"alice"}), live, provider);

    EXPECT_TRUE(resolved.known);
    EXPECT_EQ(resolved.byName.at("alice"), 900u);
}

TEST(LastLoginResolutionTests, AnOlderSessionNeverMovesTheLoginBackwards)
{
    FakeLastLoginProvider provider({{"alice", 900}});
    nlohmann::json live = nlohmann::json::array({session("alice", 500)});

    const auto resolved = resolveLastLogins(users({"alice"}), live, provider);

    EXPECT_EQ(resolved.byName.at("alice"), 900u);
}

TEST(LastLoginResolutionTests, LogoutAndBootRowsAreIgnored)
{
    // utmp keeps the logout as a DEAD_PROCESS row and the boot time as its own row. Folding either in
    // would move the anchor past the failures of the session that just ended and hide them.
    FakeLastLoginProvider provider({{"alice", 500}});
    nlohmann::json rows = nlohmann::json::array(
    {
        session("alice", 900, "dead"),
        session("alice", 950, "boot_time"),
        session("alice", 980, "init"),
        session("alice", 990, "login"),
    });

    const auto resolved = resolveLastLogins(users({"alice"}), rows, provider);

    EXPECT_EQ(resolved.byName.at("alice"), 500u);
}

TEST(LastLoginResolutionTests, SessionsOfAccountsNotCollectedAreIgnored)
{
    FakeLastLoginProvider provider({{"alice", 500}});
    nlohmann::json live = nlohmann::json::array({session("mallory", 900)});

    const auto resolved = resolveLastLogins(users({"alice"}), live, provider);

    EXPECT_EQ(resolved.byName.size(), 1u);
    EXPECT_EQ(resolved.byName.at("alice"), 500u);
}

TEST(LastLoginResolutionTests, AccountsWithoutAUsableNameAreSkipped)
{
    FakeLastLoginProvider provider({});
    nlohmann::json accounts = nlohmann::json::array(
    {
        {{"username", ""}, {"uid", 1000}},
        {{"uid", 1001}},
    });

    const auto resolved = resolveLastLogins(accounts, nlohmann::json::array(), provider);

    EXPECT_TRUE(resolved.byName.empty());
    EXPECT_FALSE(resolved.known);
}

TEST(LastLoginResolutionTests, ANegativeSessionTimeIsNotALogin)
{
    FakeLastLoginProvider provider({{"alice", 0}});
    nlohmann::json live = nlohmann::json::array({session("alice", -1)});

    const auto resolved = resolveLastLogins(users({"alice"}), live, provider);

    EXPECT_EQ(resolved.byName.at("alice"), 0u);
    EXPECT_FALSE(resolved.known);
}

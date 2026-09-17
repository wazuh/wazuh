/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sudoers_unix.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <algorithm>
#include <fstream>
#include <filesystem>

static std::string getTempFilePath()
{
    const char* tmpDir = std::getenv("TMPDIR");

    if (!tmpDir || std::strlen(tmpDir) == 0)
    {
        tmpDir = "/tmp";
    }

    std::string path = std::string(tmpDir);

    if (path.back() != '/')
    {
        path += '/';
    }

    return path;
}

static const std::string SUDOERS_FILE_PATH = getTempFilePath() + "example_sudoers";

static const std::string SUDOERS_FILE_CONTENT = R"(
#
# This file MUST be edited with the 'visudo' command as root.
#
#
Defaults	secure_path="/dir/local/sbin:/dir/local/bin:/dir/sbin:/dir/bin:/sbin:/bin:/snap/bin"

# Ditto for agent
#Defaults:%sudo env_keep += "AGENT_INFO"
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL
someuser ALL=(ALL) /dir/bin/apt update, \
                     /dir/bin/apt upgrade, \
                     /dir/bin/apt install somepackage, \
                     /dir/bin/systemctl restart someservice
# See sudoers(5) for more information on "@include" directives:
@includedir /etc/anotherDir.d
)"; // sudoers example.

class SudoersProviderTest : public ::testing::Test
{

    protected:

        SudoersProviderTest() = default;
        virtual ~SudoersProviderTest() = default;

        void SetUp() override
        {
            std::ofstream outputFile(SUDOERS_FILE_PATH);
            outputFile << SUDOERS_FILE_CONTENT;
            outputFile.close();
        };

        void TearDown() override
        {
            std::remove(SUDOERS_FILE_PATH.c_str());
        };
};

TEST_F(SudoersProviderTest, WrongFileNameReturnsEmptyArray)
{
    SudoersProvider provider("non_existent_file");
    EXPECT_EQ(provider.collect(), R"([])"_json);
}

TEST_F(SudoersProviderTest, CollectReturnsExpectedJson)
{
    SudoersProvider provider(SUDOERS_FILE_PATH);
    auto result = provider.collect();

    // Check that the result is an array
    ASSERT_TRUE(result.is_array());

    // Check that the array contains expected entries
    ASSERT_EQ(result.size(), 4u);

    auto filePath = SUDOERS_FILE_PATH.c_str();
    EXPECT_EQ(result[0]["header"], "Defaults");
    EXPECT_EQ(result[0]["source"], filePath);
    EXPECT_EQ(result[0]["rule_details"], R"(secure_path="/dir/local/sbin:/dir/local/bin:/dir/sbin:/dir/bin:/sbin:/bin:/snap/bin")");

    EXPECT_EQ(result[1]["header"], "%sudo");
    EXPECT_EQ(result[1]["source"], filePath);
    EXPECT_EQ(result[1]["rule_details"], "ALL=(ALL:ALL) ALL");

    EXPECT_EQ(result[2]["header"], "someuser");
    EXPECT_EQ(result[2]["source"], filePath);
    EXPECT_EQ(result[2]["rule_details"], "ALL=(ALL) /dir/bin/apt update, /dir/bin/apt upgrade, /dir/bin/apt install somepackage, /dir/bin/systemctl restart someservice");

    EXPECT_EQ(result[3]["header"], "@includedir");
    EXPECT_EQ(result[3]["source"], filePath);
    EXPECT_EQ(result[3]["rule_details"], "/etc/anotherDir.d");
}

static const std::string ROLES_FILE_PATH = getTempFilePath() + "example_sudoers_roles";

// The ", "-separated list ("root, backup") is the case where the parser keeps only the first entry
// in the header.
static const std::string ROLES_FILE_CONTENT = R"(
Defaults	env_reset
User_Alias	OPERATORS = alice, %ops
%admin	ALL=(ALL) ALL
vagrant	ALL=(ALL) NOPASSWD: ALL
OPERATORS	ALL=(ALL) ALL
root, backup ALL=(ALL) ALL
+remoteadmins ALL=(ALL) ALL
)";

class SudoersRolesTest : public ::testing::Test
{

    protected:

        SudoersRolesTest() = default;
        virtual ~SudoersRolesTest() = default;

        void SetUp() override
        {
            std::ofstream outputFile(ROLES_FILE_PATH);
            outputFile << ROLES_FILE_CONTENT;
            outputFile.close();
        };

        void TearDown() override
        {
            std::remove(ROLES_FILE_PATH.c_str());
        };
};

TEST_F(SudoersRolesTest, UserNamedInARuleIsASudoer)
{
    SudoersProvider provider(ROLES_FILE_PATH);
    EXPECT_TRUE(SudoersProvider::isUserSudoer(provider.collect(), "vagrant", {"staff"}));
}

TEST_F(SudoersRolesTest, UserGrantedThroughGroupMembershipIsASudoer)
{
    SudoersProvider provider(ROLES_FILE_PATH);
    EXPECT_TRUE(SudoersProvider::isUserSudoer(provider.collect(), "carol", {"staff", "admin"}));
}

TEST_F(SudoersRolesTest, UserWithoutAnyGrantIsNotASudoer)
{
    SudoersProvider provider(ROLES_FILE_PATH);
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "nobody", {"staff"}));
}

TEST_F(SudoersRolesTest, UserNameIsNotMatchedAsASubstring)
{
    SudoersProvider provider(ROLES_FILE_PATH);

    // "vagr" and "agrant" both live inside the "vagrant" rule header.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "vagr", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "agrant", {}));

    // ... and "admi" inside the "%admin" one.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "admi", {}));
}

TEST_F(SudoersRolesTest, UserAliasIsExpandedToItsMembers)
{
    SudoersProvider provider(ROLES_FILE_PATH);

    // Named directly by the alias.
    EXPECT_TRUE(SudoersProvider::isUserSudoer(provider.collect(), "alice", {"staff"}));

    // Reached through the group the alias also lists.
    EXPECT_TRUE(SudoersProvider::isUserSudoer(provider.collect(), "bob", {"ops"}));

    // The alias name itself is not an account.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "OPERATORS", {}));
}

TEST_F(SudoersRolesTest, UserListContinuingPastTheRuleHeaderIsRead)
{
    SudoersProvider provider(ROLES_FILE_PATH);

    // "root, backup ALL=(ALL) ALL" leaves only "root," in the header.
    EXPECT_TRUE(SudoersProvider::isUserSudoer(provider.collect(), "root", {}));
    EXPECT_TRUE(SudoersProvider::isUserSudoer(provider.collect(), "backup", {}));

    // The host list that closes the user list is not an account.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "ALL=(ALL)", {}));
}

TEST_F(SudoersRolesTest, UnresolvableEntriesAreNotMatched)
{
    SudoersProvider provider(ROLES_FILE_PATH);

    // A real group must not stand in for a netgroup of the same name.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "remoteadmins", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(provider.collect(), "dave", {"remoteadmins"}));
}

TEST(SudoersIsUserSudoerTest, DirectiveHeadersGrantNothing)
{
    const auto sudoers = R"([
        {"header": "Defaults", "rule_details": "env_reset", "source": "/etc/sudoers"},
        {"header": "Defaults:daemon", "rule_details": "!authenticate", "source": "/etc/sudoers"},
        {"header": "Host_Alias", "rule_details": "SERVERS = web1, web2", "source": "/etc/sudoers"},
        {"header": "Cmnd_Alias", "rule_details": "PKG = /usr/bin/apt", "source": "/etc/sudoers"},
        {"header": "@includedir", "rule_details": "/etc/sudoers.d", "source": "/etc/sudoers"}
    ])"_json;

    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "daemon", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "web1", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "Defaults", {}));
}

TEST(SudoersIsUserSudoerTest, NegatedAndNumericEntriesAreNotMatched)
{
    const auto sudoers = R"([
        {"header": "!daemon,%#80", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"},
        {"header": "operator,#501", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "daemon", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "#501", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "80", {"admin"}));
    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "operator", {}));
}

TEST(SudoersIsUserSudoerTest, LaterNegatedEntryRevokesAnEarlierGroupGrant)
{
    const auto sudoers = R"([
        {"header": "%admin,", "rule_details": "!baduser ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    // "baduser" is in the "admin" group, but the negated entry after it in the same list wins,
    // per sudoers(5) last-match-wins evaluation.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "baduser", {"admin"}));

    // Any other member of "admin" is unaffected by the negated entry naming "baduser".
    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "gooduser", {"admin"}));
}

TEST(SudoersIsUserSudoerTest, LaterPositiveEntryRegrantsAfterAnEarlierNegation)
{
    const auto sudoers = R"([
        {"header": "!baduser,", "rule_details": "%admin ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    // The negated entry comes first, but the group grant after it is the last entry that applies
    // to "baduser", so it wins -- this is what proves the evaluation is last-match-wins rather
    // than "any negation anywhere wins".
    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "baduser", {"admin"}));
}

TEST(SudoersIsUserSudoerTest, LaterNegatedEntryInASeparateRuleRevokesAnEarlierGroupGrant)
{
    const auto sudoers = R"([
        {"header": "%wheel", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"},
        {"header": "!alice,", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    // "alice" is in "wheel" and would be granted by the first rule alone, but the negated entry
    // in the later, separate rule is the one that actually applies to her last, per sudoers(5)
    // last-match-wins evaluation across the whole policy, not just within one rule's user list.
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "alice", {"wheel"}));

    // Any other member of "wheel" is unaffected by the negated entry naming "alice".
    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "bob", {"wheel"}));
}

TEST(SudoersIsUserSudoerTest, LaterGroupGrantInASeparateRuleRegrantsAfterAnEarlierNegation)
{
    const auto sudoers = R"([
        {"header": "!alice,", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"},
        {"header": "%wheel", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    // The negated rule for "alice" comes first, but the later, separate rule granting via her
    // "wheel" membership is the last rule that applies to her, so it wins.
    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "alice", {"wheel"}));
}

TEST(SudoersIsUserSudoerTest, IrrelevantLaterRuleDoesNotClobberAnEarlierApplicableGrant)
{
    const auto sudoers = R"([
        {"header": "%wheel", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"},
        {"header": "bob,", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    // "alice" is granted by the first rule via her "wheel" membership. The second rule names
    // "bob", not "alice", so it never applies to her and must leave her running state alone
    // instead of resetting it back to NoMatch/false.
    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "alice", {"wheel"}));
}

TEST(SudoersIsUserSudoerTest, NonUnixGroupIsMatchedByName)
{
    const auto sudoers = R"([
        {"header": "%:enterprise_admins", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "alice", {"enterprise_admins"}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "alice", {"staff"}));
}

TEST(SudoersIsUserSudoerTest, RuleForAllUsersGrantsEveryone)
{
    const auto sudoers = R"([
        {"header": "ALL", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "nobody", {}));
}

TEST(SudoersIsUserSudoerTest, AliasesDefinedInTermsOfEachOtherTerminate)
{
    const auto sudoers = R"([
        {"header": "User_Alias", "rule_details": "FIRST = SECOND", "source": "/etc/sudoers"},
        {"header": "User_Alias", "rule_details": "SECOND = FIRST", "source": "/etc/sudoers"},
        {"header": "FIRST", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "alice", {}));
}

TEST(SudoersIsUserSudoerTest, SeveralAliasesOnOneLineAreAllRead)
{
    const auto sudoers = R"([
        {"header": "User_Alias", "rule_details": "ADMINS = alice : AUDITORS = bob", "source": "/etc/sudoers"},
        {"header": "AUDITORS", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}
    ])"_json;

    EXPECT_TRUE(SudoersProvider::isUserSudoer(sudoers, "bob", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(sudoers, "alice", {}));
}

TEST(SudoersIsUserSudoerTest, EmptyInputsGrantNothing)
{
    EXPECT_FALSE(SudoersProvider::isUserSudoer(R"([])"_json, "root", {}));
    EXPECT_FALSE(SudoersProvider::isUserSudoer(R"([{"header": "root", "rule_details": "ALL=(ALL) ALL", "source": "/etc/sudoers"}])"_json, "", {}));
}

// Regression for genSudoersFile() joining enumerateDir()'s bare basenames with the
// includedir before recursing.
class SudoersIncludeDirTest : public ::testing::Test
{
    protected:

        SudoersIncludeDirTest() = default;
        virtual ~SudoersIncludeDirTest() = default;

        void SetUp() override
        {
            m_tempDir = std::filesystem::temp_directory_path() / "sudoers_includedir_test";
            m_includeDir = m_tempDir / "sudoers.d";
            std::filesystem::remove_all(m_tempDir);
            std::filesystem::create_directories(m_includeDir);

            m_mainFile = (m_tempDir / "sudoers").string();
            m_dropInFile = (m_includeDir / "bobby-test-39165").string();

            std::ofstream mainOut(m_mainFile);
            mainOut << "#includedir " << m_includeDir.string() << "\n";
            mainOut.close();

            std::ofstream dropInOut(m_dropInFile);
            dropInOut << "bobby ALL=(ALL) ALL\n";
            dropInOut.close();
        };

        void TearDown() override
        {
            std::filesystem::remove_all(m_tempDir);
        };

        std::filesystem::path m_tempDir;
        std::filesystem::path m_includeDir;
        std::string m_mainFile;
        std::string m_dropInFile;
};

TEST_F(SudoersIncludeDirTest, DropInFileIsReadFromItsActualIncludeDir)
{
    SudoersProvider provider(m_mainFile);
    auto result = provider.collect();

    ASSERT_TRUE(result.is_array());

    const auto dropInEntry = std::find_if(result.begin(), result.end(), [this](const nlohmann::json & entry)
    {
        return entry.value("header", "") == "bobby";
    });

    ASSERT_NE(dropInEntry, result.end());
    EXPECT_EQ((*dropInEntry)["source"], m_dropInFile);
    EXPECT_EQ((*dropInEntry)["rule_details"], "ALL=(ALL) ALL");

    EXPECT_TRUE(SudoersProvider::isUserSudoer(result, "bobby", {}));
}

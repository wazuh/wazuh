/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agent_credential_store.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#ifndef WIN32
#include <sys/stat.h>
#endif

using namespace containerimages;

namespace
{
    constexpr auto FAMILY {"container_images"};
    constexpr auto USER_KEY {"ghcr_user"};
    constexpr auto TOKEN_KEY {"ghcr_token"};
    constexpr auto TOKEN_VALUE {"ghp_averysecrettokenvalue0123456789"};

    void writeRaw(const std::filesystem::path& path, const std::string& contents)
    {
        std::ofstream file {path, std::ios::binary | std::ios::trunc};
        file << contents;
    }

    std::string readRaw(const std::filesystem::path& path)
    {
        std::ifstream file {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
    }
} // namespace

class CredentialStoreTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_directory = std::filesystem::temp_directory_path() /
                          ("ci_credentials_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + "_" +
                           ::testing::UnitTest::GetInstance()->current_test_info()->name());
            std::filesystem::remove_all(m_directory);
            std::filesystem::create_directories(m_directory);
            m_path = m_directory / "credentials.json";
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_directory);
        }

        std::filesystem::path m_directory;
        std::filesystem::path m_path;
};

#ifndef WIN32
TEST_F(CredentialStoreTest, StoredValueIsReadBackExactly)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    const auto credential {store.get(FAMILY, TOKEN_KEY)};

    ASSERT_TRUE(credential.has_value());
    EXPECT_EQ(credential->value(), TOKEN_VALUE);
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, SeveralKeysCoexistInOneFamily)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, USER_KEY, Secret {"owner"}));
    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    EXPECT_EQ(store.get(FAMILY, USER_KEY)->value(), "owner");
    EXPECT_EQ(store.get(FAMILY, TOKEN_KEY)->value(), TOKEN_VALUE);
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, ReplacingAKeyKeepsTheLatestValue)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {"first"}));
    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {"second"}));

    EXPECT_EQ(store.get(FAMILY, TOKEN_KEY)->value(), "second");
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, TheSameValueIsNotStoredAsTheSameBytes)
{
    // The helper generates a fresh key and IV per value, so two stores of the same
    // secret must not be byte-identical on disk. This is not a confidentiality claim,
    // it just pins that the cipher is really being applied.
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));
    const auto first {readRaw(m_path)};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));
    const auto second {readRaw(m_path)};

    EXPECT_NE(first, second);
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, ThePlaintextNeverAppearsInTheFile)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    EXPECT_EQ(readRaw(m_path).find(TOKEN_VALUE), std::string::npos);
}
#endif

TEST_F(CredentialStoreTest, AbsentStoreYieldsNoCredential)
{
    const AgentCredentialStore store {(m_directory / "does_not_exist.json").string()};

    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());
}

#ifndef WIN32
TEST_F(CredentialStoreTest, AbsentFamilyAndKeyYieldNoCredential)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    EXPECT_FALSE(store.get("another_family", TOKEN_KEY).has_value());
    EXPECT_FALSE(store.get(FAMILY, "another_key").has_value());
}
#endif

TEST_F(CredentialStoreTest, MalformedStoreYieldsNoCredential)
{
    const AgentCredentialStore store {m_path.string()};

    writeRaw(m_path, "{not json");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());

    writeRaw(m_path, "[1,2,3]");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());

    writeRaw(m_path, "");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());
}

TEST_F(CredentialStoreTest, ForeignShapesInTheStoreAreTolerated)
{
    const AgentCredentialStore store {m_path.string()};

    // A family that is not an object, and a key that is not a string. Neither may throw.
    writeRaw(m_path, R"({"container_images": "not-an-object"})");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());

    writeRaw(m_path, R"({"container_images": {"ghcr_token": 42}})");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());
}

TEST_F(CredentialStoreTest, NonHexAndTruncatedValuesYieldNoCredential)
{
    const AgentCredentialStore store {m_path.string()};

    writeRaw(m_path, R"({"container_images": {"ghcr_token": "not hex at all"}})");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());

    writeRaw(m_path, R"({"container_images": {"ghcr_token": "abc"}})");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());

    // Well-formed hex, but far too short to hold a key, an IV and a block.
    writeRaw(m_path, R"({"container_images": {"ghcr_token": "aabbccdd"}})");
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());
}

#ifndef WIN32
TEST_F(CredentialStoreTest, CorruptedCiphertextYieldsNoCredential)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    auto contents {readRaw(m_path)};
    const auto digit {contents.find_last_of("0123456789abcdef")};
    ASSERT_NE(digit, std::string::npos);
    contents[digit] = (contents[digit] == 'a') ? 'b' : 'a';
    writeRaw(m_path, contents);

    // Either the padding check fails or the plaintext comes back wrong. Neither may
    // throw out of get(), and a wrong value must not be returned as if it were right.
    const auto credential {store.get(FAMILY, TOKEN_KEY)};
    EXPECT_TRUE(!credential.has_value() || credential->value() != TOKEN_VALUE);
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, RemovingAKeyDropsItAndThenTheFamily)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, USER_KEY, Secret {"owner"}));
    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    EXPECT_TRUE(store.remove(FAMILY, USER_KEY));
    EXPECT_FALSE(store.get(FAMILY, USER_KEY).has_value());
    EXPECT_TRUE(store.get(FAMILY, TOKEN_KEY).has_value());

    EXPECT_TRUE(store.remove(FAMILY, TOKEN_KEY));
    EXPECT_EQ(readRaw(m_path).find(FAMILY), std::string::npos);

    EXPECT_FALSE(store.remove(FAMILY, TOKEN_KEY));
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, TheStoreDirectoryIsCreated)
{
    const auto nested {m_directory / "nested" / "deeper" / "credentials.json"};
    const AgentCredentialStore store {nested.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));
    EXPECT_TRUE(std::filesystem::exists(nested));
}
#endif

#ifndef WIN32
TEST_F(CredentialStoreTest, TheStoreIsNotReadableByOthers)
{
    const AgentCredentialStore store {m_path.string()};

    ASSERT_TRUE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));

    struct stat status {};
    ASSERT_EQ(::stat(m_path.c_str(), &status), 0);

    // Both sides as mode_t: st_mode is unsigned and the S_I* masks are signed, so
    // comparing them directly warns under -Wsign-compare.
    EXPECT_EQ(status.st_mode & static_cast<mode_t>(S_IRWXU | S_IRWXG | S_IRWXO),
              static_cast<mode_t>(S_IRUSR | S_IWUSR | S_IRGRP));
    EXPECT_EQ(status.st_mode & static_cast<mode_t>(S_IROTH), static_cast<mode_t>(0));
}
#endif

#ifdef WIN32
TEST_F(CredentialStoreTest, StoringIsRefusedOnWindows)
{
    // The module ships on Windows but its registry support does not, and the store's
    // permissions are not restricted there. Writing a credential any local user could
    // read would be worse than storing none, so put() refuses and writes nothing.
    const AgentCredentialStore store {m_path.string()};

    EXPECT_FALSE(store.put(FAMILY, TOKEN_KEY, Secret {TOKEN_VALUE}));
    EXPECT_FALSE(std::filesystem::exists(m_path));
    EXPECT_FALSE(store.get(FAMILY, TOKEN_KEY).has_value());
}
#endif

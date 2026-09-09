/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shadow_linux.hpp"
#include "ishadow_wrapper.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class MockShadowWrapper : public IShadowWrapper
{
    public:
        MOCK_METHOD(int, lckpwdf, (), (override));
        MOCK_METHOD(void, setspent, (), (override));
        MOCK_METHOD(struct spwd*, getspent, (), (override));
        MOCK_METHOD(void, endspent, (), (override));
        MOCK_METHOD(int, ulckpwdf, (), (override));
};

/// @brief Builds a shadow entry with the stock aging fields. Name and password stay pointers, so
///        pass literals.
static struct spwd makeShadow(const char* name, const char* password, long expire)
{
    struct spwd entry = {};
    entry.sp_namp = const_cast<char*>(name);
    entry.sp_pwdp = const_cast<char*>(password);
    entry.sp_lstchg = 20228;
    entry.sp_min = 0;
    entry.sp_max = 99999;
    entry.sp_warn = 7;
    entry.sp_inact = -1;
    entry.sp_expire = expire;
    return entry;
}

/// @brief Sets up one full enumeration returning a single entry.
static void expectSingleEntry(MockShadowWrapper& wrapper, struct spwd* entry)
{
    EXPECT_CALL(wrapper, lckpwdf()).WillOnce(::testing::Return(0));
    EXPECT_CALL(wrapper, setspent()).Times(1);
    EXPECT_CALL(wrapper, getspent())
    .WillOnce(::testing::Return(entry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(wrapper, endspent()).Times(1);
    EXPECT_CALL(wrapper, ulckpwdf()).WillOnce(::testing::Return(0));
}

// sp_expire is a day count read as epoch seconds, so a real expiry date was reported as 1970.
TEST(ShadowProviderTests, CollectConvertsExpirationDateToSeconds)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    // Day 20819 after the epoch is 2027-01-01.
    struct spwd entry = makeShadow("testuser", "$6$salt$hash", 20819);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["expire"], 1798761600);
}

// -1 is an empty field 8, "never expires". Must stay non-positive so consumers skip it.
TEST(ShadowProviderTests, CollectLeavesNeverExpiresUntouched)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "$6$salt$hash", -1);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["expire"], -1);
}

// Day 24856 is 2038-01-20, the first whose seconds do not fit the int wire field. The sentinel is
// reported rather than the maximum, which would be indexed as a real expiry date.
TEST(ShadowProviderTests, CollectReportsNoExpiryBeyondTheWireFieldRange)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "$6$salt$hash", 24856);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["expire"], -1);
}

// The date an admin writes for "never": day 47482 is 2100-01-01.
TEST(ShadowProviderTests, CollectReportsNoExpiryForAFarFutureSentinelDate)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "$6$salt$hash", 47482);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["expire"], -1);
}

// The last day that converts exactly, so the bound does not kick in early.
TEST(ShadowProviderTests, CollectConvertsTheLastRepresentableExpirationDate)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "$6$salt$hash", 24855);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["expire"], 2147472000);
}

// "passwd -l" keeps the hash behind a "!" marker, which the anchored regex used to drop.
TEST(ShadowProviderTests, CollectReportsHashAlgorithmForLockedAccount)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "!$6$salt$hash", -1);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "locked");
    EXPECT_EQ(result[0]["hash_alg"], "6");
}

TEST(ShadowProviderTests, CollectReportsHashAlgorithmForDoubleLockedAccount)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "!!$y$j9T$salt$hash", -1);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "locked");
    EXPECT_EQ(result[0]["hash_alg"], "y");
}

TEST(ShadowProviderTests, CollectReportsHashAlgorithmForActiveAccount)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "$6$salt$hash", -1);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "active");
    EXPECT_EQ(result[0]["hash_alg"], "6");
}

// No hash at all means no algorithm to report; this is the stock Amazon Linux case.
TEST(ShadowProviderTests, CollectReportsNoHashAlgorithmWhenPasswordHasNoHash)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd entry = makeShadow("testuser", "*", -1);
    expectSingleEntry(*mockWrapper, &entry);

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "locked");
    EXPECT_EQ(result[0]["hash_alg"], "");
}

TEST(ShadowProviderTests, CollectReturnsExpectedJson)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd fakeEntry = {};
    fakeEntry.sp_lstchg = 20228;
    fakeEntry.sp_min = 0;
    fakeEntry.sp_max = 99999;
    fakeEntry.sp_warn = 7;
    fakeEntry.sp_inact = -1;
    fakeEntry.sp_expire = -1;
    fakeEntry.sp_namp = strdup("testuser");
    // Password not_set
    fakeEntry.sp_pwdp = strdup("!!");

    EXPECT_CALL(*mockWrapper, lckpwdf())
    .WillOnce(::testing::Return(0));
    EXPECT_CALL(*mockWrapper, setspent()).Times(1);
    EXPECT_CALL(*mockWrapper, getspent())
    .WillOnce(::testing::Return(&fakeEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endspent()).Times(1);
    EXPECT_CALL(*mockWrapper, ulckpwdf())
    .WillOnce(::testing::Return(0));
    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["last_change"], 1747699200.0);
    EXPECT_EQ(result[0]["min"], 0);
    EXPECT_EQ(result[0]["max"], 99999);
    EXPECT_EQ(result[0]["warning"], 7);
    EXPECT_EQ(result[0]["inactive"], -1);
    EXPECT_EQ(result[0]["expire"], -1);
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["password_status"], "not_set");

    free(fakeEntry.sp_namp);
    free(fakeEntry.sp_pwdp);
}

TEST(ShadowProviderTests, CollectReturnsJsonArray)
{
    auto mockWrapper = std::make_shared<MockShadowWrapper>();

    struct spwd fakeEntry = {};
    fakeEntry.sp_lstchg = 20228;
    fakeEntry.sp_min = 0;
    fakeEntry.sp_max = 99999;
    fakeEntry.sp_warn = 7;
    fakeEntry.sp_inact = -1;
    fakeEntry.sp_expire = -1;
    fakeEntry.sp_namp = strdup("testuser");
    // Password active
    fakeEntry.sp_pwdp = strdup("kajdasñldjkalkd");

    struct spwd fakeEntry2 = {};
    fakeEntry2.sp_lstchg = 20228;
    fakeEntry2.sp_min = 0;
    fakeEntry2.sp_max = 99999;
    fakeEntry2.sp_warn = 7;
    fakeEntry2.sp_inact = -1;
    fakeEntry2.sp_expire = -1;
    fakeEntry2.sp_namp = strdup("testuser");
    // Password locked
    fakeEntry2.sp_pwdp = strdup("!SomePass");

    EXPECT_CALL(*mockWrapper, lckpwdf())
    .WillOnce(::testing::Return(0));
    EXPECT_CALL(*mockWrapper, setspent()).Times(1);
    EXPECT_CALL(*mockWrapper, getspent())
    .WillOnce(::testing::Return(&fakeEntry))
    .WillOnce(::testing::Return(&fakeEntry2))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endspent()).Times(1);
    EXPECT_CALL(*mockWrapper, ulckpwdf())
    .WillOnce(::testing::Return(0));

    ShadowProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[0]["last_change"], 1747699200.0);
    EXPECT_EQ(result[0]["min"], 0);
    EXPECT_EQ(result[0]["max"], 99999);
    EXPECT_EQ(result[0]["warning"], 7);
    EXPECT_EQ(result[0]["inactive"], -1);
    EXPECT_EQ(result[0]["expire"], -1);
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["password_status"], "active");

    EXPECT_EQ(result[1]["last_change"], 1747699200.0);
    EXPECT_EQ(result[1]["min"], 0);
    EXPECT_EQ(result[1]["max"], 99999);
    EXPECT_EQ(result[1]["warning"], 7);
    EXPECT_EQ(result[1]["inactive"], -1);
    EXPECT_EQ(result[1]["expire"], -1);
    EXPECT_EQ(result[1]["username"], "testuser");
    EXPECT_EQ(result[1]["password_status"], "locked");

    free(fakeEntry.sp_namp);
    free(fakeEntry.sp_pwdp);
    free(fakeEntry2.sp_namp);
    free(fakeEntry2.sp_pwdp);
}

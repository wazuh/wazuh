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

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0]["last_change"], 20228);
    EXPECT_EQ(result[0]["min"], 0);
    EXPECT_EQ(result[0]["max"], 99999);
    EXPECT_EQ(result[0]["warning"], 7);
    EXPECT_EQ(result[0]["inactive"], -1);
    EXPECT_EQ(result[0]["expire"], -1);
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["password_status"], "not_set");
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

    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0]["last_change"], 20228);
    EXPECT_EQ(result[0]["min"], 0);
    EXPECT_EQ(result[0]["max"], 99999);
    EXPECT_EQ(result[0]["warning"], 7);
    EXPECT_EQ(result[0]["inactive"], -1);
    EXPECT_EQ(result[0]["expire"], -1);
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["password_status"], "active");

    EXPECT_EQ(result[1]["last_change"], 20228);
    EXPECT_EQ(result[1]["min"], 0);
    EXPECT_EQ(result[1]["max"], 99999);
    EXPECT_EQ(result[1]["warning"], 7);
    EXPECT_EQ(result[1]["inactive"], -1);
    EXPECT_EQ(result[1]["expire"], -1);
    EXPECT_EQ(result[1]["username"], "testuser");
    EXPECT_EQ(result[1]["password_status"], "locked");
}

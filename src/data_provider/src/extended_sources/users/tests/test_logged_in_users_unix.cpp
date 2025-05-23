#include "logged_in_users_unix.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class MockUtmpxWrapper : public IUtmpxWrapper
{
    public:
        MOCK_METHOD(void, utmpxname, (const char* file), (override));
        MOCK_METHOD(void, setutxent, (), (override));
        MOCK_METHOD(void, endutxent, (), (override));
        MOCK_METHOD(struct utmpx*, getutxent, (), (override));
};

TEST(LoggedInUsersProviderTest, CollectReturnsExpectedJson)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();

    struct utmpx fakeEntry = {};
    fakeEntry.ut_type = USER_PROCESS;
    fakeEntry.ut_pid = 1234;
    strncpy(fakeEntry.ut_user, "testuser", sizeof(fakeEntry.ut_user));
    strncpy(fakeEntry.ut_line, "pts/0", sizeof(fakeEntry.ut_line));
    strncpy(fakeEntry.ut_host, "localhost", sizeof(fakeEntry.ut_host));
    fakeEntry.ut_tv.tv_sec = 1715520000;

    EXPECT_CALL(*mockWrapper, utmpxname(::testing::_)).Times(1);
    EXPECT_CALL(*mockWrapper, setutxent()).Times(1);
    EXPECT_CALL(*mockWrapper, getutxent())
    .WillOnce(::testing::Return(&fakeEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endutxent()).Times(1);

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0]["user"], "testuser");
    EXPECT_EQ(result[0]["type"], "user");
    EXPECT_EQ(result[0]["tty"], "pts/0");
    EXPECT_EQ(result[0]["host"], "localhost");
    EXPECT_EQ(result[0]["time"], 1715520000);
    EXPECT_EQ(result[0]["pid"], 1234);
}

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "igroup_wrapper_darwin.hpp"
#include "ipasswd_wrapper_darwin.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "user_groups_darwin.hpp"

using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::Invoke;

class MockGroupWrapper : public IGroupWrapperDarwin
{
    public:
        MOCK_METHOD(int, getgrouplist, (const char* user, gid_t group, gid_t* groups, int* ngroups), (const, override));
        MOCK_METHOD(int, getgroupcount, (const char* user, gid_t group), (const, override));
};

class MockPasswdWrapper : public IPasswdWrapperDarwin
{
    public:
        MOCK_METHOD(struct passwd*, getpwuid, (uid_t uid), (override));
        MOCK_METHOD(struct passwd*, getpwnam, (const char* name), (override));
};

class MockODUtilsWrapper : public IODUtilsWrapper
{
        using StringBoolMap = std::map<std::string, bool>;

    public:
        MOCK_METHOD(void,
                    genEntries,
                    (const std::string& recordType, const std::string* record, StringBoolMap& usernames),
                    (override));
};

struct passwd* createFakePasswd(const char* name, uid_t uid, gid_t gid)
{
    auto* pwd = new passwd();
    pwd->pw_name = strdup(name);
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;
    return pwd;
}

TEST(UserGroupsProviderTest, CollectWithUIDReturnsExpectedGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    uid_t test_uid = 1000;
    gid_t test_gid = 2000;
    const char* username = "testuser";

    passwd* fakePwd = createFakePasswd(username, test_uid, test_gid);
    EXPECT_CALL(*mockPasswd, getpwuid(test_uid)).WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq("testuser"), test_gid))
    .WillOnce(Return(2));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq("testuser"), test_gid, _, _))
    .WillOnce(Invoke([](const std::string&, gid_t, gid_t * groups, int* /*ngroups*/)
    {
        groups[0] = 2000;
        groups[1] = 3000;
        return 0;
    }));

    std::set<uid_t> uids = {test_uid};
    nlohmann::json result = provider.collect(uids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_EQ(result[0]["uid"], test_uid);
    EXPECT_EQ(result[0]["gid"], 2000);
    EXPECT_EQ(result[1]["gid"], 3000);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST(UserGroupsProviderTest, CollectWithoutUID_ReturnsExpectedGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    const char* username = "testuser";
    uid_t test_uid = 1001;
    gid_t test_gid = 3001;

    std::map<std::string, bool> fakeUsers = {{username, true}};

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
    .WillOnce(Invoke([&fakeUsers](const std::string&, const void*, std::map<std::string, bool>& output)
    {
        output = fakeUsers;
    }));

    passwd* fakePwd = createFakePasswd(username, test_uid, test_gid);
    EXPECT_CALL(*mockPasswd, getpwnam(::testing::StrEq(username))).WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(username), test_gid))
    .WillOnce(Return(1));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(username), test_gid, _, _))
    .WillOnce(Invoke([](const std::string&, gid_t, gid_t * groups, int* /*ngroups*/)
    {
        groups[0] = 3001;
        return 0;
    }));

    std::set<uid_t> empty_uids;
    nlohmann::json result = provider.collect(empty_uids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(1));
    EXPECT_EQ(result[0]["uid"], test_uid);
    EXPECT_EQ(result[0]["gid"], 3001);

    free(fakePwd->pw_name);
    delete fakePwd;
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

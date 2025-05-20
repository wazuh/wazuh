#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "iuser_groups_wrapper.hpp"
#include "user_groups_darwin.hpp"

using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::Invoke;

class MockUserGroupsWrapper : public IUserGroupsWrapper 
{
    public:
        MOCK_METHOD(long, sysconf, (int name), (const, override));
        MOCK_METHOD(struct passwd*, getpwuid, (uid_type uid), (const, override));
        MOCK_METHOD(int, getpwuid_r, (uid_type uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result), (const, override));
        MOCK_METHOD(void, setpwent, (), (const, override));
        MOCK_METHOD(struct passwd*, getpwent, (), (const, override));        
        MOCK_METHOD(struct passwd*, getpwnam, (const char* name), (const, override));
        MOCK_METHOD(void, endpwent, (), (const, override));
        MOCK_METHOD(int, getgroupcount, (const char* user, gid_type group), (const, override));
        MOCK_METHOD(int, getgrouplist, (const char* user, gid_type group, gid_type* groups, int* ngroups), (const, override));
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

struct passwd* createFakePasswd(const char* name, uid_type uid, gid_type gid) 
{
    auto* pwd = new passwd{};
    pwd->pw_name = strdup(name);
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;
    return pwd;
}

TEST(UserGroupsProviderTest, CollectWithUIDReturnsExpectedGroups)
{
    auto mockWrapper = std::make_shared<MockUserGroupsWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockWrapper, mockODWrapper);

    uid_type test_uid = 1000;
    gid_type test_gid = 2000;
    const char* username = "testuser";

    EXPECT_CALL(*mockWrapper, getpwuid(test_uid))
        .WillOnce(Return(createFakePasswd(username, test_uid, test_gid)));

    EXPECT_CALL(*mockWrapper, getgroupcount(::testing::StrEq("testuser"), test_gid))
        .WillOnce(Return(2));

    EXPECT_CALL(*mockWrapper, getgrouplist(::testing::StrEq("testuser"), test_gid, _, _))
        .WillOnce(Invoke([](const std::string&, gid_type, gid_type* groups, int* /*ngroups*/) {
            groups[0] = 2000;
            groups[1] = 3000;
            return 0;
        }));

    std::set<uid_type> uids = {test_uid};
    nlohmann::json result = provider.collect(uids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_EQ(result[0]["uid"], test_uid);
    EXPECT_EQ(result[0]["gid"], 2000);
    EXPECT_EQ(result[1]["gid"], 3000);
}

TEST(UserGroupsProviderTest, CollectWithoutUID_ReturnsExpectedGroups)
{
    auto mockWrapper = std::make_shared<MockUserGroupsWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockWrapper, mockODWrapper);

    const char* username = "testuser";
    uid_type test_uid = 1001;
    gid_type test_gid = 3001;

    std::map<std::string, bool> fakeUsers = {{username, true}};

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
        .WillOnce(Invoke([&fakeUsers](const std::string&, const void*, std::map<std::string, bool>& output) {
            output = fakeUsers;
        }));

    EXPECT_CALL(*mockWrapper, getpwnam(::testing::StrEq(username)))
        .WillOnce(Return(createFakePasswd(username, test_uid, test_gid)));

    EXPECT_CALL(*mockWrapper, getgroupcount(::testing::StrEq(username), test_gid))
        .WillOnce(Return(1));

    EXPECT_CALL(*mockWrapper, getgrouplist(::testing::StrEq(username), test_gid, _, _))
        .WillOnce(Invoke([](const std::string&, gid_type, gid_type* groups, int* /*ngroups*/) {
            groups[0] = 3001;
            return 0;
        }));

    std::set<uid_type> empty_uids;
    nlohmann::json result = provider.collect(empty_uids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(1));
    EXPECT_EQ(result[0]["uid"], test_uid);
    EXPECT_EQ(result[0]["gid"], 3001);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

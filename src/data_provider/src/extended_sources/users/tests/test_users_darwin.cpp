#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iuuid_wrapper.hpp"
#include "ipasswd_wrapper_darwin.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "users_darwin.hpp"

class MockUUIDWrapper : public IUUIDWrapper
{
    public:
        MOCK_METHOD(void, uidToUUID, (uid_t uid, uuid_t& uuid), (override));
        MOCK_METHOD(void, uuidToString, (const uuid_t& uuid, uuid_string_t& str), (override));
};

class MockPasswdWrapper : public IPasswdWrapperDarwin
{
    public:
        MOCK_METHOD(struct passwd*, getpwnam, (const char* name), (override));
        MOCK_METHOD(struct passwd*, getpwuid, (uid_t uid), (override));
        MOCK_METHOD(void, setpwent, (), (override));
        MOCK_METHOD(struct passwd*, getpwent, (), (override));
        MOCK_METHOD(void, endpwent, (), (override));
};

class MockODUtilsWrapper : public IODUtilsWrapper
{
        using StringBoolMap = std::map<std::string, bool>;
    public:
        MOCK_METHOD(void, genEntries,
                    (const std::string& recordType,
                     const std::string* record,
                     StringBoolMap& names),
                    (override));
};

TEST(UsersProviderTest, CollectWithConstraints_SingleUser)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockUUID = std::make_shared<MockUUIDWrapper>();
    auto mockOD = std::make_shared<MockODUtilsWrapper>();

    static struct passwd fakePasswd
    {
        .pw_name = (char*)"testuser",
        .pw_uid = 101,
        .pw_gid = 20,
        .pw_gecos = (char*)"Test User",
        .pw_dir = (char*)"/Users/testuser",
        .pw_shell = (char*)"/bin/bash"
    };

    EXPECT_CALL(*mockPasswd, getpwuid(101)).WillOnce(testing::Return(&fakePasswd));
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t& uuid)
    {
        std::fill(std::begin(uuid), std::end(uuid), 0xAB);
    });
    EXPECT_CALL(*mockUUID, uuidToString(testing::_, testing::_)).WillOnce([](const uuid_t&, uuid_string_t& str)
    {
        strcpy(str, "abcdef00-1234-5678-90ab-cdefabcdef12");
    });
    EXPECT_CALL(*mockOD, genEntries(testing::_, testing::_, testing::_)).WillOnce([](const std::string&, const std::string*, std::map<std::string, bool>& names)
    {
        names["testuser"] = false;
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({101});

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["uuid"], "abcdef00-1234-5678-90ab-cdefabcdef12");
    EXPECT_EQ(result[0]["is_hidden"], 0);
}
